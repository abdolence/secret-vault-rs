use crate::*;
use async_trait::async_trait;
use kms_aead::{
    CipherTextWithEncryptedKey, KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
};
use rvstruct::ValueStruct;

use secret_vault_value::SecretValue;

/// Envelope encryption with an AES-256-GCM data encryption key per value, wrapped by the KMS
/// key of the provider `P`. The AEAD runs on the backend the encryption is created with. Each
/// provider has an alias with its constructors, such as `gcp::GcpKmsEnvelopeEncryption`.
///
/// No data encryption key is cached: every read unwraps the key of its value with the KMS.
///
/// Errors are `EncryptionError`s with the kms-aead code, which for a failed KMS call is the
/// code the KMS returned, such as `PermissionDenied` from Google Cloud KMS or
/// `IncorrectKeyException` from AWS KMS.
pub struct SecretVaultKmsEnvelopeEncryption<P>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    envelope: KmsAeadEnvelope<P>,
}

impl<P> SecretVaultKmsEnvelopeEncryption<P>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    pub(crate) fn with_provider(provider: P, backend: AeadBackend) -> SecretVaultResult<Self> {
        let envelope = KmsAeadEnvelope::with_options(
            provider,
            backend,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm),
        )?;
        Ok(Self { envelope })
    }
}

#[async_trait]
impl<P> SecretVaultEncryption for SecretVaultKmsEnvelopeEncryption<P>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    async fn encrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let encrypted_value = self
            .envelope
            .encrypt_value(secret_vault_key.to_aad(), secret_value)
            .await?;

        Ok(encrypted_value.into())
    }

    async fn decrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        let secret_value = self
            .envelope
            .decrypt_value(
                secret_vault_key.to_aad(),
                &encrypted_secret_value.clone().into(),
            )
            .await?;
        Ok(secret_value)
    }
}

impl From<CipherTextWithEncryptedKey> for EncryptedSecretValue {
    fn from(cipher_text: CipherTextWithEncryptedKey) -> Self {
        EncryptedSecretValue(cipher_text.into_value())
    }
}

impl From<EncryptedSecretValue> for CipherTextWithEncryptedKey {
    fn from(encrypted_value: EncryptedSecretValue) -> Self {
        CipherTextWithEncryptedKey(encrypted_value.into_value())
    }
}

/// The name of a local key encryption key.
pub type LocalKekId = kms_aead::providers::LocalKekId;
/// The version of a local key encryption key.
pub type LocalKekVersion = kms_aead::providers::LocalKekVersion;
/// One version of a local key encryption key, read from a file, an environment variable or a
/// secret the application holds.
pub type LocalKek = kms_aead::providers::LocalKek;

/// Envelope encryption with the data encryption keys wrapped by a key encryption key the process
/// holds, for development, tests and single-host installs without a cloud KMS.
///
/// The limits of [`kms_aead::providers::LocalKmsProvider`] apply: each value the vault stores, on
/// every refresh, costs one wrap under the KEK.
pub type LocalKmsEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::LocalKmsProvider>;

impl LocalKmsEnvelopeEncryption {
    /// Wraps the data encryption keys with the KEK `id`, whose highest version in `keks` wraps
    /// and every version unwraps, with AES-256-GCM on `backend` for both the values and the keys.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when `keks` is empty or lists a version twice.
    pub fn new(
        id: LocalKekId,
        keks: Vec<LocalKek>,
        backend: AeadBackend,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(
            kms_aead::providers::LocalKmsProvider::new(id, keks, backend)?,
            backend,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SecretVaultError;
    use std::num::NonZeroU32;

    fn local_kms_encryption() -> SecretVaultResult<LocalKmsEnvelopeEncryption> {
        let kek = LocalKek::from_secret(
            LocalKekVersion::from(NonZeroU32::MIN),
            SecretValue::new(vec![42; 32]),
        )?;
        LocalKmsEnvelopeEncryption::new(
            LocalKekId::try_from("secret-vault-test".to_string())?,
            vec![kek],
            TEST_BACKEND,
        )
    }

    #[tokio::test]
    async fn value_round_trips_through_local_kms_envelope() -> SecretVaultResult<()> {
        let encryption = local_kms_encryption()?;
        let secret_vault_key = SecretVaultKey::new(SecretName::from_static("my-app/database"));
        let secret_value = SecretValue::from("test-secret");

        let encrypted_value = encryption
            .encrypt_value(&secret_vault_key, &secret_value)
            .await?;
        assert_ne!(encrypted_value.value(), secret_value.ref_sensitive_value());

        let decrypted_value = encryption
            .decrypt_value(&secret_vault_key, &encrypted_value)
            .await?;
        assert_eq!(decrypted_value, secret_value);
        Ok(())
    }

    #[tokio::test]
    async fn value_does_not_decrypt_under_another_secret_name() -> SecretVaultResult<()> {
        let encryption = local_kms_encryption()?;
        let secret_value = SecretValue::from("test-secret");

        let encrypted_value = encryption
            .encrypt_value(
                &SecretVaultKey::new(SecretName::from_static("my-app/database")),
                &secret_value,
            )
            .await?;
        let decrypted = encryption
            .decrypt_value(
                &SecretVaultKey::new(SecretName::from_static("my-app/api-key")),
                &encrypted_value,
            )
            .await;
        assert!(
            matches!(&decrypted, Err(SecretVaultError::EncryptionError(e)) if e.public.code == "DECRYPT"),
            "{decrypted:?}"
        );
        Ok(())
    }
}

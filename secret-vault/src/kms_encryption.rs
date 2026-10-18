use crate::backends::AeadBackend;
use crate::*;
use async_trait::async_trait;
use kms_aead::formats::Envelope;
use kms_aead::{Encrypted, KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadEnvelopeOptions};

use secret_vault_value::SecretValue;

/// Envelope encryption with an AES-256-GCM DEK per value, which the KMS key of the provider `P`
/// encrypts, with the AEAD on the backend `B`. Each provider has an alias with its constructors,
/// such as `gcp::GcpKmsEnvelopeEncryption<B>`.
///
/// No DEK is cached: every read decrypts the encrypted DEK of its value with the KMS.
///
/// Errors keep the kms-aead code, which for a failed KMS call is the code the KMS returned. A KMS
/// that could not be reached, timed out or throttled is a `NetworkError`, which may be retried;
/// a permission, not-found or invalid-key failure, such as `PermissionDenied` from Google Cloud
/// KMS or `IncorrectKeyException` from AWS KMS, is an `EncryptionError`.
pub struct SecretVaultKmsEnvelopeEncryption<P, B> {
    envelope: KmsAeadEnvelope<P, B>,
}

impl<P, B> SecretVaultKmsEnvelopeEncryption<P, B>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    pub(crate) fn with_provider(provider: P) -> SecretVaultResult<Self> {
        let envelope = KmsAeadEnvelope::with_options(
            provider,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm),
        )?;
        Ok(Self { envelope })
    }
}

#[async_trait]
impl<P, B> SecretVaultEncryption for SecretVaultKmsEnvelopeEncryption<P, B>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    async fn encrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let encrypted_value = self
            .envelope
            .encrypt(secret_vault_key.to_aad(), secret_value)
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
            .decrypt(
                secret_vault_key.to_aad(),
                &Encrypted::<SecretValue, Envelope>::try_from(encrypted_secret_value.clone())?,
            )
            .await?;
        Ok(secret_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SecretVaultError;
    use kms_aead::providers::{LocalKekId, LocalKmsProvider};
    use rvstruct::ValueStruct;

    #[tokio::test]
    async fn value_round_trips_through_local_kms_envelope() -> SecretVaultResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::ephemeral(LocalKekId::try_from(
            "secret-vault-test".to_string(),
        )?)?;
        let encryption =
            SecretVaultKmsEnvelopeEncryption::<_, TestBackend>::with_provider(provider)?;
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
        let provider = LocalKmsProvider::<TestBackend>::ephemeral(LocalKekId::try_from(
            "secret-vault-test".to_string(),
        )?)?;
        let encryption =
            SecretVaultKmsEnvelopeEncryption::<_, TestBackend>::with_provider(provider)?;
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

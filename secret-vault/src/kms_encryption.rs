use crate::*;
use async_trait::async_trait;
use kms_aead::{
    KmsAeadEnvelopeEncryption, KmsAeadRingEncryptionProvider, KmsAeadRingEnvelopeEncryption,
};

use secret_vault_value::SecretValue;

/// Envelope encryption with an AES-256-GCM data encryption key per value, wrapped by the KMS
/// key of the provider `P`. Each provider has an alias with its constructors, such as
/// `gcp::GcpKmsEnvelopeEncryption`.
pub struct SecretVaultKmsEnvelopeEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    envelope_aead_encryption: KmsAeadRingEnvelopeEncryption<P>,
}

impl<P> SecretVaultKmsEnvelopeEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    pub(crate) async fn with_provider(provider: P) -> SecretVaultResult<Self> {
        let envelope_aead_encryption =
            KmsAeadRingEnvelopeEncryption::with_algorithm(provider, &ring::aead::AES_256_GCM)
                .await?;

        Ok(Self {
            envelope_aead_encryption,
        })
    }
}

#[async_trait]
impl<P> SecretVaultEncryption for SecretVaultKmsEnvelopeEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    async fn encrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let encrypted_value = self
            .envelope_aead_encryption
            .encrypt_value(&secret_vault_key.to_aad(), secret_value)
            .await?;

        Ok(encrypted_value.into())
    }

    async fn decrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        let secret_value = self
            .envelope_aead_encryption
            .decrypt_value(
                &secret_vault_key.to_aad(),
                &encrypted_secret_value.clone().into(),
            )
            .await?;
        Ok(secret_value)
    }
}

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use kms_aead::KmsAeadEnvelopeEncryption;

use secret_vault_value::SecretValue;

pub type GcpKmsKeyRef = kms_aead::providers::GcpKmsKeyRef;

pub struct GcpKmsEnvelopeEncryption {
    envelope_aead_encryption:
        kms_aead::KmsAeadRingEnvelopeEncryption<kms_aead::providers::GcpKmsProvider>,
}

impl GcpKmsEnvelopeEncryption {
    /// Fails with [`SecretVaultError::InvalidParametersError`] when `hashicorp-vault-tls-ring`
    /// is in the build and the application has not installed a default `CryptoProvider`, for
    /// the reason given on [`crate::gcp::GcpSecretManagerSource::with_options`].
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> SecretVaultResult<Self> {
        #[cfg(feature = "hashicorp-vault-tls-ring")]
        crate::crypto_provider::require_installed_crypto_provider()?;

        let provider = kms_aead::providers::GcpKmsProvider::new(kms_key_ref)
            .await
            .map_err(SecretVaultError::from)?;
        let envelope_aead_encryption = kms_aead::KmsAeadRingEnvelopeEncryption::with_algorithm(
            provider,
            &ring::aead::AES_256_GCM,
        )
        .await
        .map_err(SecretVaultError::from)?;

        Ok(Self {
            envelope_aead_encryption,
        })
    }
}

#[async_trait]
impl SecretVaultEncryption for GcpKmsEnvelopeEncryption {
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

use rvstruct::ValueStruct;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use kms_aead::KmsAeadEnvelopeEncryption;

use secret_vault_value::SecretValue;

pub type GcpKmsKeyRef = kms_aead::providers::GcpKmsKeyRef;

pub struct GcpKmsEnvelopeEncryption {
    envelope_aead_encryption: kms_aead::KmsAeadRingEncryption<kms_aead::providers::GcpKmsProvider>,
}

impl GcpKmsEnvelopeEncryption {
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> SecretVaultResult<Self> {
        let provider = kms_aead::providers::GcpKmsProvider::new(kms_key_ref)
            .await
            .map_err(|e| SecretVaultError::from(e))?;
        let envelope_aead_encryption = kms_aead::KmsAeadRingEncryption::new(provider)
            .await
            .map_err(|e| SecretVaultError::from(e))?;

        Ok(Self {
            envelope_aead_encryption,
        })
    }
}

#[async_trait]
impl SecretVaultEncryption for GcpKmsEnvelopeEncryption {
    async fn encrypt_value(
        &self,
        secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let (encrypted_value, _) = self
            .envelope_aead_encryption
            .encrypt_value(secret_name.value().into(), secret_value)
            .await?;

        Ok(encrypted_value.into())
    }

    async fn decrypt_value(
        &self,
        secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        let (secret_value, _) = self
            .envelope_aead_encryption
            .decrypt_value(
                secret_name.value().into(),
                &encrypted_secret_value.clone().into(),
            )
            .await?;
        Ok(secret_value)
    }
}
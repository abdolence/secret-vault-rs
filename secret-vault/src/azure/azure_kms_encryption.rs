use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;
use azure_core::credentials::TokenCredential;
use std::sync::Arc;

pub type AzureKmsKeyRef = kms_aead::providers::AzureKmsKeyRef;
pub type AzureKmsProviderOptions = kms_aead::providers::AzureKmsProviderOptions;
pub type KmsKeyVersion = kms_aead::KmsKeyVersion;

pub type AzureKmsEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AzureKmsProvider>;

impl AzureKmsEnvelopeEncryption {
    /// Wraps the data encryption keys with the key at `kms_key_ref`, using any Azure credential,
    /// for example one from `azure_identity`. No request is made until the first value is
    /// encrypted.
    pub async fn new(
        kms_key_ref: &AzureKmsKeyRef,
        credential: Arc<dyn TokenCredential>,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AzureKmsProvider::new(
            kms_key_ref,
            credential,
        )?)
        .await
    }

    /// Same as [`Self::new`], with the wrap algorithm and the Azure SDK client settings taken
    /// from `options`.
    pub async fn with_options(
        kms_key_ref: &AzureKmsKeyRef,
        options: AzureKmsProviderOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AzureKmsProvider::with_options(
            kms_key_ref,
            options,
            credential,
        )?)
        .await
    }
}

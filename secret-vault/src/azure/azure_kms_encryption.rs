use crate::backends::AeadBackend;
use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;
use azure_core::credentials::TokenCredential;
use std::sync::Arc;

pub type AzureKmsKeyRef = kms_aead::providers::AzureKmsKeyRef;
pub type AzureKmsProviderOptions = kms_aead::providers::AzureKmsProviderOptions;
pub type KmsKeyVersion = kms_aead::providers::KmsKeyVersion;

/// Envelope encryption with the data encryption keys wrapped by an Azure Key Vault or Managed HSM
/// key, with the values sealed on the backend `B`.
pub type AzureKmsEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AzureKmsProvider, B>;

impl<B: AeadBackend> AzureKmsEnvelopeEncryption<B> {
    /// Wraps the data encryption keys with the key at `kms_key_ref`, using any Azure credential,
    /// for example one from `azure_identity`. No request is made until the first value is
    /// encrypted.
    ///
    /// # Errors
    ///
    /// As [`Self::with_options`].
    pub fn new(
        kms_key_ref: &AzureKmsKeyRef,
        credential: Arc<dyn TokenCredential>,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AzureKmsProvider::new(
            kms_key_ref,
            credential,
        )?)
    }

    /// Same as [`Self::new`], with the wrap algorithm and the Azure SDK client settings taken
    /// from `options`.
    ///
    /// # Errors
    ///
    /// `AZURE_KEY_NAME` when the key name holds characters Key Vault does not allow in it,
    /// `AZURE_WRAP_ALGORITHM` when the algorithm is `Rsa1_5` or unknown, and `AZURE_VAULT_URL`
    /// when the vault URL is not an HTTP(S) URL.
    pub fn with_options(
        kms_key_ref: &AzureKmsKeyRef,
        options: AzureKmsProviderOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AzureKmsProvider::with_options(
            kms_key_ref,
            options,
            credential,
        )?)
    }
}

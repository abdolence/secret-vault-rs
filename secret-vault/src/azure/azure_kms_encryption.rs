use crate::backends::AeadBackend;
use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;
use azure_core::credentials::TokenCredential;
use std::sync::Arc;

pub type AzureKmsAlgorithm = kms_aead::providers::AzureKmsAlgorithm;
pub type AzureKmsKeyRef = kms_aead::providers::AzureKmsKeyRef;
pub type AzureKmsProviderOptions = kms_aead::providers::AzureKmsProviderOptions;
pub type KekVersion = kms_aead::providers::KekVersion;

/// Envelope encryption with a DEK per value, which an Azure Key Vault or Managed HSM key encrypts,
/// with the values encrypted on the backend `B`.
pub type AzureKmsEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AzureKmsProvider, B>;

impl<B: AeadBackend> AzureKmsEnvelopeEncryption<B> {
    /// Encrypts and decrypts the DEKs with the key at `kms_key_ref`, using any Azure credential,
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
    /// `AZURE_KEY_NAME` when the key name holds characters Key Vault does not allow in it, and
    /// `AZURE_VAULT_URL` when the vault URL is not an HTTP(S) URL.
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

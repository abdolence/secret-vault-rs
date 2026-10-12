use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type VaultTransitKeyRef = kms_aead::providers::VaultTransitKeyRef;
pub type VaultTransitProviderOptions = kms_aead::providers::VaultTransitProviderOptions;
pub type VaultTransitToken = kms_aead::providers::VaultTransitToken;

pub type VaultTransitEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::VaultTransitProvider>;

impl VaultTransitEnvelopeEncryption {
    /// Same as [`Self::with_options`] with [`VaultTransitProviderOptions::from_env`], which
    /// reads `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` and `VAULT_CACERT`.
    pub async fn new(key_ref: &VaultTransitKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::VaultTransitProvider::new(key_ref)?).await
    }

    /// Wraps the data encryption keys with the Transit key at `key_ref`. No request is made
    /// until the first value is encrypted, so a wrong token or an unreachable server fail the
    /// first refresh of the vault.
    pub async fn with_options(
        key_ref: &VaultTransitKeyRef,
        options: VaultTransitProviderOptions,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::VaultTransitProvider::with_options(
            key_ref, options,
        )?)
        .await
    }
}

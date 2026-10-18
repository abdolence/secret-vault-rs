use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type HcVaultTransitKeyRef = kms_aead::providers::HcVaultTransitKeyRef;
pub type HcVaultTransitProviderOptions = kms_aead::providers::HcVaultTransitProviderOptions;
pub type HcVaultTransitToken = kms_aead::providers::HcVaultTransitToken;

/// Envelope encryption with the data encryption keys wrapped by a HashiCorp Vault Transit key,
/// with the values sealed on the backend `B`.
pub type HcVaultTransitEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::HcVaultTransitProvider, B>;

impl<B: AeadBackend> HcVaultTransitEnvelopeEncryption<B> {
    /// Same as [`Self::with_options`] with [`HcVaultTransitProviderOptions::from_env`], which
    /// reads `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` and `VAULT_CACERT`.
    ///
    /// # Errors
    ///
    /// As [`HcVaultTransitProviderOptions::from_env`] and [`Self::with_options`].
    pub fn new(key_ref: &HcVaultTransitKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::HcVaultTransitProvider::new(key_ref)?)
    }

    /// Wraps the data encryption keys with the Transit key at `key_ref`. No request is made until
    /// the first value is encrypted, so a wrong token or an unreachable server fail the first
    /// refresh of the vault.
    ///
    /// # Errors
    ///
    /// `VAULT_INVALID_OPTIONS` on an invalid address, mount, key name, namespace or timeout, an
    /// unreadable CA certificate file, or no CA certificate to trust at all, and `VAULT_TLS` when
    /// the TLS configuration cannot be built.
    pub fn with_options(
        key_ref: &HcVaultTransitKeyRef,
        options: HcVaultTransitProviderOptions,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::HcVaultTransitProvider::with_options(
            key_ref, options,
        )?)
    }
}

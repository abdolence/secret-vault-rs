use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type HcVaultTransitKeyRef = kms_aead::providers::HcVaultTransitKeyRef;
pub type HcVaultTransitProviderOptions = kms_aead::providers::HcVaultTransitProviderOptions;
pub type HcVaultTransitToken = kms_aead::providers::HcVaultTransitToken;

pub type HcVaultTransitEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::HcVaultTransitProvider>;

impl HcVaultTransitEnvelopeEncryption {
    /// Same as [`Self::with_options`] with [`HcVaultTransitProviderOptions::from_env`], which
    /// reads `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` and `VAULT_CACERT`.
    ///
    /// # Errors
    ///
    /// As [`HcVaultTransitProviderOptions::from_env`] and [`Self::with_options`].
    pub fn new(key_ref: &HcVaultTransitKeyRef, backend: AeadBackend) -> SecretVaultResult<Self> {
        Self::with_provider(
            kms_aead::providers::HcVaultTransitProvider::new(key_ref)?,
            backend,
        )
    }

    /// Wraps the data encryption keys with the Transit key at `key_ref` and seals the values on
    /// `backend`. No request is made until the first value is encrypted, so a wrong token or an
    /// unreachable server fail the first refresh of the vault.
    ///
    /// # Errors
    ///
    /// `VAULT_INVALID_OPTIONS` on an invalid address, mount, key name, namespace or timeout, an
    /// unreadable CA certificate file, or no CA certificate to trust at all, and `VAULT_TLS` when
    /// the TLS configuration cannot be built.
    pub fn with_options(
        key_ref: &HcVaultTransitKeyRef,
        options: HcVaultTransitProviderOptions,
        backend: AeadBackend,
    ) -> SecretVaultResult<Self> {
        Self::with_provider(
            kms_aead::providers::HcVaultTransitProvider::with_options(key_ref, options)?,
            backend,
        )
    }
}

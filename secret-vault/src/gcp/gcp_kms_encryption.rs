use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type GcpKmsKeyRef = kms_aead::providers::GcpKmsKeyRef;

pub type GcpKmsEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::GcpKmsProvider>;

impl GcpKmsEnvelopeEncryption {
    /// Wraps the data encryption keys with the Cloud KMS CryptoKey at `kms_key_ref`, through a
    /// client authenticated with the application default credentials, with the values sealed on
    /// `backend`.
    ///
    /// # Errors
    ///
    /// An `EncryptionError` when the client cannot be built, such as when no credentials are
    /// found.
    pub async fn new(kms_key_ref: &GcpKmsKeyRef, backend: AeadBackend) -> SecretVaultResult<Self> {
        Self::with_provider(
            kms_aead::providers::GcpKmsProvider::new(kms_key_ref).await?,
            backend,
        )
    }
}

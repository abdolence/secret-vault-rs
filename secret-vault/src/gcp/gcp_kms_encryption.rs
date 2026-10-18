use crate::backends::AeadBackend;
use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type GcpKmsKeyRef = kms_aead::providers::GcpKmsKeyRef;

/// Envelope encryption with the data encryption keys wrapped by a Google Cloud KMS CryptoKey,
/// with the values sealed on the backend `B`.
pub type GcpKmsEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::GcpKmsProvider, B>;

impl<B: AeadBackend> GcpKmsEnvelopeEncryption<B> {
    /// Wraps the data encryption keys with the Cloud KMS CryptoKey at `kms_key_ref`, through a
    /// client authenticated with the application default credentials.
    ///
    /// # Errors
    ///
    /// An `EncryptionError` when the client cannot be built, such as when no credentials are
    /// found.
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::GcpKmsProvider::new(kms_key_ref).await?)
    }
}

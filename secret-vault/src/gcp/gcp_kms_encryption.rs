use crate::backends::AeadBackend;
use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type GcpKmsKeyRef = kms_aead::providers::GcpKmsKeyRef;

/// Envelope encryption with a DEK per value, which a Google Cloud KMS CryptoKey encrypts, with the
/// values encrypted on the backend `B`.
pub type GcpKmsEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::GcpKmsProvider, B>;

impl<B: AeadBackend> GcpKmsEnvelopeEncryption<B> {
    /// Encrypts and decrypts the DEKs with the Cloud KMS CryptoKey at `kms_key_ref`, through a
    /// client authenticated with the application default credentials.
    ///
    /// # Errors
    ///
    /// A `SystemError` when the client cannot be built, such as when no credentials are found.
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::GcpKmsProvider::new(kms_key_ref).await?)
    }
}

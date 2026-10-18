use crate::backends::AeadBackend;
use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type AwsKmsKeyRef = kms_aead::providers::AwsKmsKeyRef;

/// Envelope encryption with a DEK per value, which an AWS KMS key encrypts, with the values
/// encrypted on the backend `B`.
pub type AwsKmsEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AwsKmsProvider, B>;

impl<B: AeadBackend> AwsKmsEnvelopeEncryption<B> {
    /// Encrypts and decrypts the DEKs with the AWS KMS key at `kms_key_ref`, with the AWS
    /// configuration from the environment. No request is made until the first value is
    /// encrypted.
    pub async fn new(kms_key_ref: &AwsKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AwsKmsProvider::new(kms_key_ref).await?)
    }
}

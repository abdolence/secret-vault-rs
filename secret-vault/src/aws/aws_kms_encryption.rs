use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type AwsKmsKeyRef = kms_aead::providers::AwsKmsKeyRef;

/// Envelope encryption with the data encryption keys wrapped by an AWS KMS key, with the values
/// sealed on the backend `B`.
pub type AwsKmsEnvelopeEncryption<B> =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AwsKmsProvider, B>;

impl<B: AeadBackend> AwsKmsEnvelopeEncryption<B> {
    /// Wraps the data encryption keys with the AWS KMS key at `kms_key_ref`, with the AWS
    /// configuration from the environment. No request is made until the first value is
    /// encrypted.
    pub async fn new(kms_key_ref: &AwsKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AwsKmsProvider::new(kms_key_ref).await?)
    }
}

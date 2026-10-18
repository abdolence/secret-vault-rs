use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type AwsKmsKeyRef = kms_aead::providers::AwsKmsKeyRef;

pub type AwsKmsEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AwsKmsProvider>;

impl AwsKmsEnvelopeEncryption {
    /// Wraps the data encryption keys with the AWS KMS key at `kms_key_ref`, with the AWS
    /// configuration from the environment, and seals the values on `backend`. No request is
    /// made until the first value is encrypted.
    pub async fn new(kms_key_ref: &AwsKmsKeyRef, backend: AeadBackend) -> SecretVaultResult<Self> {
        Self::with_provider(
            kms_aead::providers::AwsKmsProvider::new(kms_key_ref).await?,
            backend,
        )
    }
}

use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type AwsKmsKeyRef = kms_aead::providers::AwsKmsKeyRef;

pub type AwsKmsEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::AwsKmsProvider>;

impl AwsKmsEnvelopeEncryption {
    pub async fn new(kms_key_ref: &AwsKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::AwsKmsProvider::new(kms_key_ref).await?).await
    }
}

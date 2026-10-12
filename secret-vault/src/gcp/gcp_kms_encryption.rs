use crate::kms_encryption::SecretVaultKmsEnvelopeEncryption;
use crate::*;

pub type GcpKmsKeyRef = kms_aead::providers::GcpKmsKeyRef;

pub type GcpKmsEnvelopeEncryption =
    SecretVaultKmsEnvelopeEncryption<kms_aead::providers::GcpKmsProvider>;

impl GcpKmsEnvelopeEncryption {
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_provider(kms_aead::providers::GcpKmsProvider::new(kms_key_ref).await?).await
    }
}

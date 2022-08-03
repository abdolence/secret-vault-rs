use crate::common_types::SecretName;

use crate::SecretVaultResult;
use async_trait::async_trait;
use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub SecretValue);

#[derive(Debug, Clone, PartialEq, ValueStruct)]
pub struct WrappedSessionKey(pub SecretValue);

#[async_trait]
pub trait SecretVaultEncryption {
    async fn encrypt_value(
        &self,
        secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue>;

    async fn decrypt_value(
        &self,
        secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue>;
}

#[derive(Debug)]
pub struct SecretVaultNoEncryption;

#[async_trait]
impl SecretVaultEncryption for SecretVaultNoEncryption {
    async fn encrypt_value(
        &self,
        _secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        Ok(EncryptedSecretValue(secret_value.clone()))
    }

    async fn decrypt_value(
        &self,
        _secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        Ok(encrypted_secret_value.value().clone())
    }
}

#[cfg(any(feature = "kms", feature = "encrypted-ring"))]
impl From<kms_aead::EncryptedSecretValue> for EncryptedSecretValue {
    fn from(kms_aead_value: kms_aead::EncryptedSecretValue) -> Self {
        EncryptedSecretValue(kms_aead_value.value().to_owned())
    }
}

#[cfg(any(feature = "kms", feature = "encrypted-ring"))]
impl From<EncryptedSecretValue> for kms_aead::EncryptedSecretValue {
    fn from(encrypted_value: EncryptedSecretValue) -> Self {
        kms_aead::EncryptedSecretValue(encrypted_value.value().to_owned())
    }
}

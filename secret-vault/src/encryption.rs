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

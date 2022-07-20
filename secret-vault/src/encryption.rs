use crate::common_types::SecretName;

use crate::SecretVaultResult;
use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub SecretValue);

pub trait SecretVaultEncryption {
    fn encrypt_value(
        &self,
        secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue>;

    fn decrypt_value(
        &self,
        secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue>;
}

#[derive(Debug)]
pub struct NoEncryption;

impl SecretVaultEncryption for NoEncryption {
    fn encrypt_value(
        &self,
        _secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        Ok(EncryptedSecretValue(secret_value.clone()))
    }

    fn decrypt_value(
        &self,
        _secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        Ok(encrypted_secret_value.value().clone())
    }
}

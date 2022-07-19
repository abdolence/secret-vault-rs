use crate::common_types::SecretName;

use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub SecretValue);

pub trait SecretVaultEncryption {
    fn encrypt_value(
        &self,
        secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> EncryptedSecretValue;
    fn decrypt_value(
        &self,
        secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretValue;
}

pub struct NoEncryption;

impl SecretVaultEncryption for NoEncryption {
    fn encrypt_value(
        &self,
        _secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> EncryptedSecretValue {
        EncryptedSecretValue(secret_value.clone())
    }

    fn decrypt_value(
        &self,
        _secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretValue {
        encrypted_secret_value.value().clone()
    }
}

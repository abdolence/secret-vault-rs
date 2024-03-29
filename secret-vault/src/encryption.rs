use crate::{SecretVaultKey, SecretVaultResult};
use async_trait::async_trait;
use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub Vec<u8>);

impl SecretVaultKey {
    #[inline]
    pub fn to_aad(&self) -> &String {
        self.secret_name.value()
    }
}

#[async_trait]
pub trait SecretVaultEncryption {
    async fn encrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue>;

    async fn decrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue>;
}

#[derive(Debug)]
pub struct SecretVaultNoEncryption;

#[async_trait]
impl SecretVaultEncryption for SecretVaultNoEncryption {
    async fn encrypt_value(
        &self,
        _secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        Ok(EncryptedSecretValue::from(
            secret_value.ref_sensitive_value().clone(),
        ))
    }

    async fn decrypt_value(
        &self,
        _secret_vault_key: &SecretVaultKey,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        Ok(SecretValue::from(encrypted_secret_value.value().clone()))
    }
}

#[cfg(any(feature = "kms", feature = "ring-aead-encryption"))]
impl From<kms_aead::CipherText> for EncryptedSecretValue {
    fn from(kms_aead_value: kms_aead::CipherText) -> Self {
        EncryptedSecretValue(kms_aead_value.value().to_owned())
    }
}

#[cfg(any(feature = "kms", feature = "ring-aead-encryption"))]
impl From<kms_aead::CipherTextWithEncryptedKey> for EncryptedSecretValue {
    fn from(kms_aead_value: kms_aead::CipherTextWithEncryptedKey) -> Self {
        EncryptedSecretValue(kms_aead_value.value().to_owned())
    }
}

#[cfg(any(feature = "kms", feature = "ring-aead-encryption"))]
impl From<EncryptedSecretValue> for kms_aead::CipherText {
    fn from(encrypted_value: EncryptedSecretValue) -> Self {
        kms_aead::CipherText(encrypted_value.value().to_owned())
    }
}

#[cfg(any(feature = "kms", feature = "ring-aead-encryption"))]
impl From<EncryptedSecretValue> for kms_aead::CipherTextWithEncryptedKey {
    fn from(encrypted_value: EncryptedSecretValue) -> Self {
        kms_aead::CipherTextWithEncryptedKey(encrypted_value.value().to_owned())
    }
}

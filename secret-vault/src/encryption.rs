use crate::{SecretVaultKey, SecretVaultResult};
use async_trait::async_trait;
use rvstruct::*;
use secret_vault_value::SecretValue;
use std::fmt;

/// A secret as the vault stores it: ciphertext, or the plaintext itself under
/// [`SecretVaultNoEncryption`]. `Debug` prints `***` in place of the bytes.
///
/// The vault wipes the bytes it stores when it replaces or drops them, but this type does not
/// wipe itself: bytes moved or cloned out of it are the caller's to zeroize.
#[derive(Clone, Eq, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub Vec<u8>);

impl fmt::Debug for EncryptedSecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedSecretValue(***)")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_stored_bytes() {
        let stored = EncryptedSecretValue(b"plaintext-secret".to_vec());

        let printed = format!("{stored:?}");

        assert!(!printed.contains("plaintext-secret"));
        assert!(!printed.contains(&format!("{:?}", stored.0)));
    }
}

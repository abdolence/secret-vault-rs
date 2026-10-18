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

/// The crypto library that seals the stored values, selected at runtime among the ones the `ring`,
/// `aws-lc`, `aws-lc-fips` and `rustcrypto` features compile in.
#[cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "aws-lc-fips",
    feature = "rustcrypto"
))]
pub type AeadBackend = kms_aead::AeadBackend;

/// The AEAD algorithm of [`aead_encryption::SecretVaultAeadEncryption`](crate::aead_encryption::SecretVaultAeadEncryption).
#[cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "aws-lc-fips",
    feature = "rustcrypto"
))]
pub type AeadAlgorithm = kms_aead::AeadAlgorithm;

/// The backend the encryption tests run on: one of the backends the build has.
#[cfg(all(test, feature = "ring"))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::Ring;
#[cfg(all(
    test,
    not(feature = "ring"),
    any(feature = "aws-lc", feature = "aws-lc-fips")
))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::AwsLc;
#[cfg(all(
    test,
    not(feature = "ring"),
    not(feature = "aws-lc"),
    not(feature = "aws-lc-fips"),
    feature = "rustcrypto"
))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::RustCrypto;

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

use crate::{SecretVaultKey, SecretVaultResult};
use async_trait::async_trait;
use rvstruct::*;
use secret_vault_value::SecretValue;
use std::fmt;

/// A secret as the vault stores it: ciphertext, or the plaintext itself under
/// [`SecretVaultNoEncryption`]. `Debug` prints `***` in place of the bytes.
///
/// The vault wipes the bytes it stores when it replaces or drops them, but this type does not
/// wipe itself: bytes moved or cloned out of it are the caller's to zeroise.
#[derive(Clone, Eq, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub Vec<u8>);

impl fmt::Debug for EncryptedSecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedSecretValue(***)")
    }
}

/// Stores the bytes of a value in the format `F`, as they are.
#[cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "aws-lc-fips",
    feature = "rustcrypto"
))]
impl<F: kms_aead::formats::Format> From<kms_aead::Encrypted<SecretValue, F>>
    for EncryptedSecretValue
{
    fn from(encrypted: kms_aead::Encrypted<SecretValue, F>) -> Self {
        EncryptedSecretValue(encrypted.into_value())
    }
}

/// Reads the stored bytes as a value of the format `F`.
///
/// # Errors
///
/// The errors of kms-aead's `TryFrom<Vec<u8>>` for `Encrypted`, such as
/// `INVALID_CIPHER_TEXT_FORMAT` for bytes outside the layout of `F`.
#[cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "aws-lc-fips",
    feature = "rustcrypto"
))]
impl<F: kms_aead::formats::Format> TryFrom<EncryptedSecretValue>
    for kms_aead::Encrypted<SecretValue, F>
{
    type Error = kms_aead::errors::KmsAeadError;

    fn try_from(stored: EncryptedSecretValue) -> Result<Self, Self::Error> {
        kms_aead::Encrypted::try_from(stored.into_value())
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

#[cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "aws-lc-fips",
    feature = "rustcrypto"
))]
pub use kms_aead::AeadAlgorithm;

/// The backend the encryption tests run on: one of the backends the build has.
#[cfg(all(test, feature = "ring"))]
pub(crate) type TestBackend = crate::backends::Ring;
#[cfg(all(
    test,
    not(feature = "ring"),
    any(feature = "aws-lc", feature = "aws-lc-fips")
))]
pub(crate) type TestBackend = crate::backends::AwsLc;
#[cfg(all(
    test,
    not(feature = "ring"),
    not(feature = "aws-lc"),
    not(feature = "aws-lc-fips"),
    feature = "rustcrypto"
))]
pub(crate) type TestBackend = crate::backends::RustCrypto;

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

    #[cfg(any(
        feature = "ring",
        feature = "aws-lc",
        feature = "aws-lc-fips",
        feature = "rustcrypto"
    ))]
    #[test]
    fn stored_bytes_outside_the_layout_are_refused() {
        use kms_aead::errors::KmsAeadError;
        use kms_aead::formats::Bare;
        use kms_aead::Encrypted;

        let read = Encrypted::<SecretValue, Bare>::try_from(EncryptedSecretValue(vec![0; 8]));

        assert!(
            matches!(&read, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
            "{read:?}"
        );
    }
}

use async_trait::async_trait;
use kms_aead::formats::Bare;
use kms_aead::{AeadCipher, DataEncryptionKey, Encrypted};
use secret_vault_value::SecretValue;

use crate::backends::AeadBackend;
use crate::{
    AeadAlgorithm, EncryptedSecretValue, SecretVaultEncryption, SecretVaultKey, SecretVaultResult,
};

/// Encrypts the stored values with an AEAD algorithm on the backend `B`, under one key generated
/// when the encryption is created and held in memory until it is dropped. Each value is bound to
/// its secret name, the additional authenticated data, so it only decrypts under the key it was
/// stored with.
///
/// Errors are `EncryptionError`s with the kms-aead code, such as `DECRYPT` for a value that is not
/// authentic under the key and the secret name.
pub struct SecretVaultAeadEncryption<B> {
    cipher: AeadCipher<B>,
    dek: DataEncryptionKey,
}

impl<B: AeadBackend> SecretVaultAeadEncryption<B> {
    /// AES-256-GCM, under a new key from the backend's CSPRNG.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn new() -> SecretVaultResult<Self> {
        Self::with_algorithm(AeadAlgorithm::Aes256Gcm)
    }

    /// `algorithm`, under a new key from the backend's CSPRNG.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when the backend does not implement `algorithm`, such as `Ring`
    /// for AES-256-GCM-SIV, and `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn with_algorithm(algorithm: AeadAlgorithm) -> SecretVaultResult<Self> {
        let cipher = AeadCipher::new(algorithm)?;
        let dek = cipher.generate_dek()?;
        Ok(Self { cipher, dek })
    }
}

#[async_trait]
impl<B: AeadBackend> SecretVaultEncryption for SecretVaultAeadEncryption<B> {
    async fn encrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let encrypted =
            self.cipher
                .encrypt_bare(secret_vault_key.to_aad(), secret_value, &self.dek)?;
        Ok(encrypted.into())
    }

    async fn decrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        Ok(self.cipher.decrypt_bare(
            secret_vault_key.to_aad(),
            &Encrypted::<SecretValue, Bare>::try_from(encrypted_secret_value.clone())?,
            &self.dek,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SecretVaultError;
    use crate::source_tests::*;
    use crate::{SecretName, TestBackend};
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rvstruct::ValueStruct;

    async fn encryption_test_for(mock_secret_value: SecretValue) -> SecretVaultResult<()> {
        let mock_secret_name: SecretName = "test".to_string().into();
        let mock_secret_vault_key: SecretVaultKey = SecretVaultKey::new(mock_secret_name);

        let encryption = SecretVaultAeadEncryption::<TestBackend>::new()?;

        let encrypted_value = encryption
            .encrypt_value(&mock_secret_vault_key, &mock_secret_value)
            .await?;
        assert_ne!(
            encrypted_value.value(),
            mock_secret_value.ref_sensitive_value()
        );

        let decrypted_value = encryption
            .decrypt_value(&mock_secret_vault_key, &encrypted_value)
            .await?;
        assert_eq!(
            decrypted_value.ref_sensitive_value(),
            mock_secret_value.ref_sensitive_value()
        );
        Ok(())
    }

    #[tokio::test]
    async fn secret_encryption_test() -> SecretVaultResult<()> {
        let mut runner = TestRunner::default();
        encryption_test_for(
            generate_secret_value()
                .new_tree(&mut runner)
                .unwrap()
                .current(),
        )
        .await
    }

    #[tokio::test]
    async fn big_secret_encryption_test() -> SecretVaultResult<()> {
        for sz in [5000, 32768, 65535] {
            encryption_test_for(SecretValue::new("42".repeat(sz).as_bytes().to_vec())).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn value_encrypted_under_static_key_decrypts_under_equal_runtime_key(
    ) -> SecretVaultResult<()> {
        let static_key = SecretVaultKey::from_parts(SecretName::from_static("test"), None, None);
        let runtime_key = SecretVaultKey::new(String::from("test").into());
        let mock_secret_value = SecretValue::new("42".repeat(1024).as_bytes().to_vec());

        let encryption = SecretVaultAeadEncryption::<TestBackend>::new()?;
        let encrypted_value = encryption
            .encrypt_value(&static_key, &mock_secret_value)
            .await?;
        let decrypted_value = encryption
            .decrypt_value(&runtime_key, &encrypted_value)
            .await?;
        assert_eq!(
            decrypted_value.ref_sensitive_value(),
            mock_secret_value.ref_sensitive_value()
        );
        Ok(())
    }

    #[tokio::test]
    async fn wrong_secret_name_test_attest() -> SecretVaultResult<()> {
        let mock_secret_name1: SecretName = "test1".to_string().into();
        let mock_secret_name2: SecretName = "test2".to_string().into();
        let mock_secret_vault_key1: SecretVaultKey = SecretVaultKey::new(mock_secret_name1);
        let mock_secret_vault_key2: SecretVaultKey = SecretVaultKey::new(mock_secret_name2);

        let mock_secret_value = SecretValue::new("42".repeat(1024).as_bytes().to_vec());

        let encryption = SecretVaultAeadEncryption::<TestBackend>::new()?;
        let encrypted_value = encryption
            .encrypt_value(&mock_secret_vault_key1, &mock_secret_value)
            .await?;
        let decrypted = encryption
            .decrypt_value(&mock_secret_vault_key2, &encrypted_value)
            .await;
        assert!(
            matches!(&decrypted, Err(SecretVaultError::EncryptionError(e)) if e.public.code == "DECRYPT"),
            "{decrypted:?}"
        );
        Ok(())
    }
}

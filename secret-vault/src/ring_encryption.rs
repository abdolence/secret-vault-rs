use crate::{SecretVaultKey, SecretVaultResult};

use async_trait::async_trait;
use kms_aead::ring_encryption::KmsAeadRingAeadEncryption;
use kms_aead::{DataEncryptionKey, KmsAeadEncryption};
use ring::rand::SystemRandom;
use secret_vault_value::*;

use crate::encryption::*;

pub struct SecretVaultRingAeadEncryption {
    ring_encryption: KmsAeadRingAeadEncryption,
    vault_secret: DataEncryptionKey,
}

impl SecretVaultRingAeadEncryption {
    pub fn new() -> SecretVaultResult<Self> {
        Self::with_algorithm(&ring::aead::CHACHA20_POLY1305)
    }

    pub fn with_algorithm(algo: &'static ring::aead::Algorithm) -> SecretVaultResult<Self> {
        let ring_encryption = KmsAeadRingAeadEncryption::with_algorithm(algo, SystemRandom::new())?;
        let vault_secret = ring_encryption.generate_data_encryption_key()?;

        Ok(Self {
            ring_encryption,
            vault_secret,
        })
    }
}

#[async_trait]
impl SecretVaultEncryption for SecretVaultRingAeadEncryption {
    async fn encrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let encrypted = self
            .ring_encryption
            .encrypt_value(secret_vault_key.to_aad(), secret_value, &self.vault_secret)
            .await?;
        Ok(encrypted.into())
    }

    async fn decrypt_value(
        &self,
        secret_vault_key: &SecretVaultKey,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        Ok(self
            .ring_encryption
            .decrypt_value(
                secret_vault_key.to_aad(),
                &encrypted_secret_value.clone().into(),
                &self.vault_secret,
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_tests::*;
    use crate::SecretName;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rvstruct::*;

    async fn encryption_test_for(mock_secret_value: SecretValue) {
        let mock_secret_name: SecretName = "test".to_string().into();
        let mock_secret_vault_key: SecretVaultKey = SecretVaultKey::new(mock_secret_name);

        let encryption = SecretVaultRingAeadEncryption::new().unwrap();

        let encrypted_value = encryption
            .encrypt_value(&mock_secret_vault_key, &mock_secret_value)
            .await
            .unwrap();
        assert_ne!(
            encrypted_value.value(),
            mock_secret_value.ref_sensitive_value()
        );

        let decrypted_value = encryption
            .decrypt_value(&mock_secret_vault_key, &encrypted_value)
            .await
            .unwrap();
        assert_eq!(
            decrypted_value.ref_sensitive_value(),
            mock_secret_value.ref_sensitive_value()
        );
    }

    #[tokio::test]
    async fn secret_encryption_test() {
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
    async fn big_secret_encryption_test() {
        for sz in vec![5000, 32768, 65535] {
            encryption_test_for(SecretValue::new("42".repeat(sz).as_bytes().to_vec())).await
        }
    }

    #[tokio::test]
    async fn wrong_secret_name_test_attest() {
        let mock_secret_name1: SecretName = "test1".to_string().into();
        let mock_secret_name2: SecretName = "test2".to_string().into();
        let mock_secret_vault_key1: SecretVaultKey = SecretVaultKey::new(mock_secret_name1);
        let mock_secret_vault_key2: SecretVaultKey = SecretVaultKey::new(mock_secret_name2);

        let mock_secret_value = SecretValue::new("42".repeat(1024).as_bytes().to_vec());

        let encryption = SecretVaultRingAeadEncryption::new().unwrap();
        let encrypted_value = encryption
            .encrypt_value(&mock_secret_vault_key1, &mock_secret_value)
            .await
            .unwrap();
        encryption
            .decrypt_value(&mock_secret_vault_key2, &encrypted_value)
            .await
            .expect_err("Unable to decrypt data");
    }
}

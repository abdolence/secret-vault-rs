use crate::common_types::*;
use crate::errors::*;
use crate::SecretVaultResult;

use ring::aead::{BoundKey, OpeningKey, SealingKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rvstruct::ValueStruct;
use secret_vault_value::*;

use crate::encryption::*;

pub struct SecretVaultRingAeadEncryption {
    session_secret: SecretValue,
    nonce_data: SecretValue,
}

impl SecretVaultRingAeadEncryption {
    const SESSION_KEY_LEN: usize = 32;

    pub fn new() -> SecretVaultResult<Self> {
        let secure_rand = SystemRandom::new();
        let session_secret = Self::generate_session_secret(&secure_rand)?;

        let mut nonce_data: [u8; ring::aead::NONCE_LEN] = [0; ring::aead::NONCE_LEN];
        secure_rand.fill(&mut nonce_data).map_err(|e| {
            SecretVaultEncryptionError::create(
                "ENCRYPTION",
                format!("Unable to initialise random nonce: {:?}", e).as_str(),
            )
        })?;

        Ok(Self {
            session_secret,
            nonce_data: SecretValue::new(nonce_data.to_vec()),
        })
    }

    fn generate_session_secret(secure_rand: &SystemRandom) -> SecretVaultResult<SecretValue> {
        let mut rand_key_data: [u8; Self::SESSION_KEY_LEN] = [0; Self::SESSION_KEY_LEN];
        secure_rand.fill(&mut rand_key_data).map_err(|e| {
            SecretVaultEncryptionError::create(
                "ENCRYPTION",
                format!("Unable to initialise random session key: {:?}", e).as_str(),
            )
        })?;
        Ok(SecretValue::new(Vec::from(rand_key_data)))
    }
}

impl SecretVaultEncryption for SecretVaultRingAeadEncryption {
    fn encrypt_value(
        &self,
        secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let mut encrypted_secret_value = secret_value.clone();

        let mut sealing_key = SealingKey::new(
            UnboundKey::new(
                &ring::aead::CHACHA20_POLY1305,
                self.session_secret.ref_sensitive_value(),
            )
            .map_err(|e| {
                SecretVaultEncryptionError::create(
                    "ENCRYPT_KEY",
                    format!("Unable to create a sealing key: {:?}", e).as_str(),
                )
            })?,
            OneNonceSequence::new(
                ring::aead::Nonce::try_assume_unique_for_key(self.nonce_data.ref_sensitive_value())
                    .map_err(|e| {
                        SecretVaultEncryptionError::create(
                            "ENCRYPT_KEY",
                            format!("Unable to create a nonce for a sealing key: {:?}", e).as_str(),
                        )
                    })?,
            ),
        );

        sealing_key
            .seal_in_place_append_tag(
                ring::aead::Aad::from(secret_name),
                encrypted_secret_value.ref_sensitive_value_mut(),
            )
            .map_err(|e| {
                SecretVaultEncryptionError::create(
                    "ENCRYPT",
                    format!("Unable to encrypt data: {:?}", e).as_str(),
                )
            })?;
        Ok(encrypted_secret_value.into())
    }

    fn decrypt_value(
        &self,
        secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        let mut secret_value: SecretValue = encrypted_secret_value.value().clone();

        let mut opening_key = OpeningKey::new(
            UnboundKey::new(
                &ring::aead::CHACHA20_POLY1305,
                self.session_secret.ref_sensitive_value(),
            )
            .map_err(|e| {
                SecretVaultEncryptionError::create(
                    "DECRYPT_KEY",
                    format!("Unable to create an opening key: {:?}", e).as_str(),
                )
            })?,
            OneNonceSequence::new(
                ring::aead::Nonce::try_assume_unique_for_key(self.nonce_data.ref_sensitive_value())
                    .map_err(|e| {
                        SecretVaultEncryptionError::create(
                            "DECRYPT_KEY",
                            format!("Unable to create an opening key: {:?}", e).as_str(),
                        )
                    })?,
            ),
        );

        opening_key
            .open_in_place(
                ring::aead::Aad::from(secret_name),
                secret_value.ref_sensitive_value_mut(),
            )
            .map_err(|e| {
                SecretVaultEncryptionError::create(
                    "DECRYPT",
                    format!("Unable to decrypt data: {:?}", e).as_str(),
                )
            })?;

        let len = secret_value.ref_sensitive_value().len();
        secret_value
            .ref_sensitive_value_mut()
            .truncate(len - ring::aead::MAX_TAG_LEN);
        Ok(secret_value)
    }
}

struct OneNonceSequence(Option<ring::aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: ring::aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

impl AsRef<[u8]> for &SecretName {
    fn as_ref(&self) -> &[u8] {
        self.value().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn generate_secret_value() -> BoxedStrategy<SecretValue> {
        ("[a-zA-Z0-9]*")
            .prop_map(|(mock_secret_str)| SecretValue::new(mock_secret_str.as_bytes().to_vec()))
            .boxed()
    }

    fn encryption_test_for(mock_secret_value: SecretValue) {
        let mock_secret_name: SecretName = "test".to_string().into();
        let encryption = SecretVaultRingAeadEncryption::new().unwrap();

        let encrypted_value = encryption
            .encrypt_value(&mock_secret_name, &mock_secret_value)
            .unwrap();
        assert_ne!(*encrypted_value.value(), mock_secret_value);

        let decrypted_value = encryption
            .decrypt_value(&mock_secret_name, &encrypted_value)
            .unwrap();
        assert_eq!(
            decrypted_value.ref_sensitive_value(),
            mock_secret_value.ref_sensitive_value()
        );
    }

    proptest! {

        #[test]
        fn secret_encryption_test(mock_secret_value in generate_secret_value()) {
            encryption_test_for(mock_secret_value)
        }
    }

    #[test]
    fn big_secret_encryption_test() {
        for sz in vec![5000, 32768, 65535] {
            encryption_test_for(SecretValue::new("42".repeat(sz).as_bytes().to_vec()))
        }
    }

    #[test]
    fn wrong_secret_name_test_attest() {
        let mock_secret_name1: SecretName = "test1".to_string().into();
        let mock_secret_name2: SecretName = "test2".to_string().into();

        let mock_secret_value = SecretValue::new("42".repeat(1024).as_bytes().to_vec());

        let encryption = SecretVaultRingAeadEncryption::new().unwrap();
        let encrypted_value = encryption
            .encrypt_value(&mock_secret_name1, &mock_secret_value)
            .unwrap();
        encryption
            .decrypt_value(&mock_secret_name2, &encrypted_value)
            .expect_err("Unable to decrypt data");
    }
}

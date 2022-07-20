use std::collections::HashMap;

use crate::common_types::*;
use crate::encryption::*;
use crate::SecretVaultResult;

#[derive(Debug)]
pub struct SecretVaultStoreValue {
    pub data: EncryptedSecretValue,
    pub metadata: SecretMetadata,
}

#[derive(Debug)]
pub struct SecretVaultStore<E>
where
    E: SecretVaultEncryption,
{
    secrets: HashMap<SecretVaultRef, SecretVaultStoreValue>,
    encrypter: E,
}

impl<E> SecretVaultStore<E>
where
    E: SecretVaultEncryption,
{
    pub fn new(encrypter: E) -> Self {
        Self {
            secrets: HashMap::new(),
            encrypter,
        }
    }

    pub fn insert(&mut self, secret_ref: SecretVaultRef, secret: &Secret) -> SecretVaultResult<()> {
        let encrypted_secret_value = self
            .encrypter
            .encrypt_value(&secret_ref.secret_name, &secret.value)?;
        self.secrets.insert(
            secret_ref,
            SecretVaultStoreValue {
                data: encrypted_secret_value,
                metadata: SecretMetadata::new(),
            },
        );

        Ok(())
    }

    pub fn get_secret(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>> {
        match self.secrets.get(secret_ref) {
            Some(stored_value) => {
                let secret_value = self
                    .encrypter
                    .decrypt_value(&secret_ref.secret_name, &stored_value.data)?;
                Ok(Some(Secret::new(
                    secret_value,
                    stored_value.metadata.clone(),
                )))
            }
            None => Ok(None),
        }
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }
}

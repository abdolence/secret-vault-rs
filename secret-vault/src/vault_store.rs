use crate::allocator::*;
use std::collections::HashMap;

use crate::common_types::*;
use crate::encryption::*;
use crate::SecretVaultResult;

#[derive(Debug)]
pub struct SecretVaultStore<AR, E>
where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
{
    secrets: HashMap<SecretVaultRef, SecretVaultStoreValue<AR::R>>,
    encrypter: E,
    allocator: AR,
}

impl<AR, E> SecretVaultStore<AR, E>
where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
{
    pub fn new(encrypter: E, allocator: AR) -> Self {
        Self {
            secrets: HashMap::new(),
            encrypter,
            allocator,
        }
    }

    pub fn insert(&mut self, secret_ref: SecretVaultRef, secret: &Secret) -> SecretVaultResult<()> {
        let encrypted_secret_value = self
            .encrypter
            .encrypt_value(&secret_ref.secret_name, &secret.value)?;
        let allocated_data = self.allocator.allocate(encrypted_secret_value)?;
        self.secrets.insert(
            secret_ref,
            SecretVaultStoreValue {
                data: allocated_data,
                metadata: SecretMetadata::new(),
            },
        );

        Ok(())
    }

    pub fn get_secret(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>> {
        match self.secrets.get(secret_ref) {
            Some(stored_value) => {
                let secret_value = self.encrypter.decrypt_value(
                    &secret_ref.secret_name,
                    &self.allocator.extract(&stored_value.data)?,
                )?;
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

use crate::allocator::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;

use crate::common_types::*;
use crate::encryption::*;
use crate::SecretVaultResult;

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

    pub fn insert(
        &mut self,
        secret_ref: SecretVaultRef,
        secret: &SecretValue,
    ) -> SecretVaultResult<()> {
        let encrypted_secret_value = self
            .encrypter
            .encrypt_value(&secret_ref.secret_name, secret)?;
        self.secrets
            .insert(secret_ref, self.allocator.allocate(encrypted_secret_value)?);

        Ok(())
    }

    pub fn get_secret(
        &self,
        secret_ref: &SecretVaultRef,
    ) -> SecretVaultResult<Option<SecretValue>> {
        match self.secrets.get(secret_ref) {
            Some(encrypted_stored_value) => Ok(Some(self.encrypter.decrypt_value(
                &secret_ref.secret_name,
                &self.allocator.extract(encrypted_stored_value)?,
            )?)),
            None => Ok(None),
        }
    }
}

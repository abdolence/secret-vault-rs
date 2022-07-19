use crate::allocator::{
    SecretVaultStoreValue, SecretVaultStoreValueAllocator, SecretVaultStoreValueNoAllocator,
};
use rsb_derive::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;

use crate::common_types::*;
use crate::encryption::{EncryptedSecretValue, NoEncryption, SecretVaultEncryption};
use crate::errors::SecretVaultError;
use crate::SecretVaultResult;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretVaultStoreRef {
    pub secret_name: SecretName,
    pub secret_version: Option<SecretVersion>,
}

pub struct SecretVaultStore<
    R = EncryptedSecretValue,
    AR = SecretVaultStoreValueNoAllocator,
    E = NoEncryption,
> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
{
    secrets: HashMap<SecretVaultStoreRef, SecretVaultStoreValue<R>>,
    encrypter: E,
    allocator: AR,
}

impl<R, AR, E> SecretVaultStore<R, AR, E>
where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator<R = R>,
{
    pub fn new(encrypter: E, allocator: AR) -> Self {
        Self {
            secrets: HashMap::new(),
            encrypter,
            allocator,
        }
    }

    pub fn store(
        &mut self,
        secret_ref: SecretVaultStoreRef,
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
        secret_ref: SecretVaultStoreRef,
    ) -> SecretVaultResult<Option<SecretValue>> {
        match self.secrets.get(&secret_ref) {
            Some(encrypted_stored_value) => Ok(Some(self.encrypter.decrypt_value(
                &secret_ref.secret_name,
                &self.allocator.extract(encrypted_stored_value)?,
            )?)),
            None => Ok(None),
        }
    }
}

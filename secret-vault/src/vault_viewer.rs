use secret_vault_value::SecretValue;
use crate::{SecretName, SecretVaultEncryption, SecretVaultRef, SecretVaultResult, SecretVaultStoreValueAllocator, SecretVersion};
use crate::vault_store::SecretVaultStore;

#[derive(Clone)]
pub struct SecretVaultViewer<'a, AR, E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {
    store: &'a SecretVaultStore<AR, E>,
}

impl<'a, AR, E> SecretVaultViewer<'a, AR,E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {

    pub fn new(store: &'a SecretVaultStore<AR, E>) -> Self {
        Self {
            store
        }
    }

    pub fn get_secret(&self, secret_name: &SecretName) -> SecretVaultResult<Option<SecretValue>> {
        self.get_secret_with_version(secret_name, None)
    }

    pub fn get_secret_with_version(&self, secret_name: &SecretName, secret_version: Option<&SecretVersion>) -> SecretVaultResult<Option<SecretValue>> {
        self.get_secret_by_ref(&SecretVaultRef::new(secret_name.clone()).opt_secret_version(secret_version.cloned()))
    }

    pub fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<SecretValue>> {
        self.store.get_secret(secret_ref)
    }
}

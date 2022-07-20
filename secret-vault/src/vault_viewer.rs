use secret_vault_value::SecretValue;
use crate::{SecretName, SecretVaultEncryption, SecretVaultRef, SecretVaultResult, SecretVaultStoreValueAllocator, SecretVersion};
use crate::vault_store::SecretVaultStore;

pub trait SecretVaultView {

    fn get_secret(&self, secret_name: &SecretName) -> SecretVaultResult<Option<SecretValue>> {
        self.get_secret_with_version(secret_name, None)
    }

    fn get_secret_with_version(&self, secret_name: &SecretName, secret_version: Option<&SecretVersion>) -> SecretVaultResult<Option<SecretValue>> {
        self.get_secret_by_ref(&SecretVaultRef::new(secret_name.clone()).opt_secret_version(secret_version.cloned()))
    }

    fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<SecretValue>>;
}

pub struct SecretVaultViewer<'a, AR, E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {
    store_ref: &'a SecretVaultStore<AR, E>
}

impl<'a, AR, E> SecretVaultViewer<'a, AR,E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {

    pub fn new(store: &'a SecretVaultStore<AR, E>) -> Self {
        Self {
            store_ref: store
        }
    }
}

impl<'a, AR, E> SecretVaultView for SecretVaultViewer<'a, AR, E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {

    fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<SecretValue>> {
        self.store_ref.get_secret(secret_ref)
    }
}

pub struct SecretVaultSnapshot<AR, E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {
    store: SecretVaultStore<AR, E>
}

impl<AR, E> SecretVaultSnapshot<AR,E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {

    pub fn new(store: SecretVaultStore<AR, E>) -> Self {
        Self {
            store: store
        }
    }
}

impl<AR, E> SecretVaultView for SecretVaultSnapshot<AR, E> where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator {

    fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<SecretValue>> {
        self.store.get_secret(secret_ref)
    }
}

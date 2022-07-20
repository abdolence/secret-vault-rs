use crate::allocator::SecretVaultStoreValueAllocator;
use crate::encryption::SecretVaultEncryption;
use crate::secrets_source::SecretsSource;
use crate::vault_store::SecretVaultStore;
use crate::{SecretVaultRef, SecretVaultResult, SecretVaultViewer};
use tracing::*;
use secret_vault_value::SecretValue;

pub struct SecretVault<S, AR, E>
where
    S: SecretsSource,
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
{
    source: S,
    store: SecretVaultStore<AR, E>,
    refs: Vec<SecretVaultRef>,
}

impl<S, AR, E> SecretVault<S, AR, E>
where
    S: SecretsSource,
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
{
    pub fn new(source: S, store: SecretVaultStore<AR, E>) -> SecretVaultResult<Self> {
        Ok(Self { source, store, refs: Vec::new() })
    }

    pub fn with_secrets_refs(&mut self, secret_refs: Vec<&SecretVaultRef>) -> &mut Self {
        self.refs = secret_refs.into_iter().map(|e| e.clone()).collect();
        self
    }

    pub async fn refresh(&mut self) -> SecretVaultResult<&mut Self> {
        debug!("Refreshing secrets from the source: {}", self.source.name());

        let mut secrets_map = self.source.get_secrets(
            &self.refs
        ).await?;

        for (secret_ref, secret_value) in secrets_map.drain() {
            self.store.insert(secret_ref, &secret_value)?;
        }

        Ok(self)
    }

    pub fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<SecretValue>> {
        self.store.get_secret(secret_ref)
    }

    pub fn viewer(&self) -> SecretVaultViewer<AR, E> {
        SecretVaultViewer::new(&self.store)
    }

}

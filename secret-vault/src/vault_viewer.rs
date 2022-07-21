use crate::vault_store::SecretVaultStore;
use crate::*;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait SecretVaultView {
    async fn get_secret(&self, secret_name: &SecretName) -> SecretVaultResult<Option<Secret>> {
        self.get_secret_with_version(secret_name, None).await
    }

    async fn get_secret_with_version(
        &self,
        secret_name: &SecretName,
        secret_version: Option<&SecretVersion>,
    ) -> SecretVaultResult<Option<Secret>> {
        self.get_secret_by_ref(
            &SecretVaultRef::new(secret_name.clone()).opt_secret_version(secret_version.cloned()),
        )
        .await
    }

    async fn get_secret_by_ref(
        &self,
        secret_ref: &SecretVaultRef,
    ) -> SecretVaultResult<Option<Secret>>;
}

#[derive(Clone)]
pub struct SecretVaultViewer<E>
where
    E: SecretVaultEncryption,
{
    store: Arc<SecretVaultStore<E>>,
}

impl<E> SecretVaultViewer<E>
where
    E: SecretVaultEncryption,
{
    pub fn new(store: Arc<SecretVaultStore<E>>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<E> SecretVaultView for SecretVaultViewer<E>
where
    E: SecretVaultEncryption + Send + Sync,
{
    async fn get_secret_by_ref(
        &self,
        secret_ref: &SecretVaultRef,
    ) -> SecretVaultResult<Option<Secret>> {
        self.store.get_secret(secret_ref).await
    }
}

use crate::vault_store::SecretVaultStore;
use crate::*;
use async_trait::async_trait;

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

pub struct SecretVaultViewer<'a, E>
where
    E: SecretVaultEncryption,
{
    store_ref: &'a SecretVaultStore<E>,
}

impl<'a, E> SecretVaultViewer<'a, E>
where
    E: SecretVaultEncryption,
{
    pub fn new(store: &'a SecretVaultStore<E>) -> Self {
        Self { store_ref: store }
    }
}

#[async_trait]
impl<'a, E> SecretVaultView for SecretVaultViewer<'a, E>
where
    E: SecretVaultEncryption + Send + Sync,
{
    async fn get_secret_by_ref(
        &self,
        secret_ref: &SecretVaultRef,
    ) -> SecretVaultResult<Option<Secret>> {
        self.store_ref.get_secret(secret_ref).await
    }
}

pub struct SecretVaultSnapshot<E>
where
    E: SecretVaultEncryption,
{
    store: SecretVaultStore<E>,
}

impl<E> SecretVaultSnapshot<E>
where
    E: SecretVaultEncryption,
{
    pub fn new(store: SecretVaultStore<E>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<E> SecretVaultView for SecretVaultSnapshot<E>
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

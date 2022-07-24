use crate::encryption::SecretVaultEncryption;
use crate::secrets_source::SecretsSource;
use crate::vault_store::SecretVaultStore;
use crate::*;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::*;

pub struct SecretVault<S, E>
where
    S: SecretsSource,
    E: SecretVaultEncryption + Sync + Send,
{
    source: S,
    store: Arc<SecretVaultStore<E>>,
    refs: Vec<SecretVaultRef>,
}

impl<S, E> SecretVault<S, E>
where
    S: SecretsSource,
    E: SecretVaultEncryption + Sync + Send,
{
    pub fn new(source: S, encrypter: E) -> SecretVaultResult<Self> {
        Ok(Self {
            source,
            store: Arc::new(SecretVaultStore::new(encrypter)),
            refs: Vec::new(),
        })
    }

    pub fn with_secrets_refs(mut self, secret_refs: Vec<&SecretVaultRef>) -> Self {
        self.refs = secret_refs.into_iter().cloned().collect();
        self
    }

    pub fn register_secrets_refs(&mut self, secret_refs: Vec<&SecretVaultRef>) -> &mut Self {
        self.refs = secret_refs.into_iter().cloned().collect();
        self
    }

    pub async fn refresh(&self) -> SecretVaultResult<&Self> {
        info!(
            "Refreshing secrets from the source: {}. Expected: {}. Required: {}",
            self.source.name(),
            self.refs.len(),
            self.refs
                .iter()
                .filter(|secret_ref| secret_ref.required)
                .count()
        );

        let mut secrets_map = self.source.get_secrets(&self.refs).await?;

        for (secret_ref, secret) in secrets_map.drain() {
            self.store.insert(secret_ref, &secret).await?;
        }

        info!("Secret vault contains: {} secrets", self.store.len().await);

        Ok(self)
    }

    pub async fn refresh_only(
        &self,
        predicate: fn(&SecretVaultRef) -> bool,
    ) -> SecretVaultResult<&Self> {
        let refs_auto_refresh_enabled: Vec<SecretVaultRef> = self
            .refs
            .iter()
            .filter(|secret_ref| predicate(secret_ref))
            .cloned()
            .collect();

        trace!(
            "Refreshing secrets from the source: {}. All registered secrets: {}. Expected to be refreshed: {}",
            self.source.name(),
            self.refs.len(),
            refs_auto_refresh_enabled.len()
        );

        let mut secrets_map = self.source.get_secrets(&refs_auto_refresh_enabled).await?;

        for (secret_ref, secret) in secrets_map.drain() {
            self.store.insert(secret_ref, &secret).await?;
        }

        trace!(
            "Secret vault now contains: {} secrets in total",
            self.store.len().await
        );

        Ok(self)
    }

    pub async fn store_len(&self) -> usize {
        self.store.len().await
    }

    pub fn viewer(&self) -> SecretVaultViewer<E> {
        SecretVaultViewer::new(self.store.clone())
    }
}

#[async_trait]
impl<S, E> SecretVaultView for SecretVault<S, E>
where
    S: SecretsSource + Send + Sync,
    E: SecretVaultEncryption + Send + Sync,
{
    async fn get_secret_by_ref(
        &self,
        secret_ref: &SecretVaultRef,
    ) -> SecretVaultResult<Option<Secret>> {
        self.store.get_secret(secret_ref).await
    }
}

#[cfg(test)]
mod tests {
    use crate::source_tests::*;
    use crate::*;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    #[tokio::test]
    async fn refresh_vault_test() {
        let mut runner = TestRunner::default();
        let mock_secrets_store = generate_mock_secrets_source()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let mut vault = SecretVaultBuilder::with_source(mock_secrets_store.clone())
            .build()
            .unwrap();

        vault
            .register_secrets_refs(mock_secrets_store.secrets.keys().into_iter().collect())
            .refresh()
            .await
            .unwrap();

        for secret_ref in mock_secrets_store.secrets.keys() {
            assert_eq!(
                vault
                    .get_secret_by_ref(secret_ref)
                    .await
                    .unwrap()
                    .map(|secret| secret.value)
                    .as_ref(),
                mock_secrets_store.secrets.get(secret_ref)
            )
        }
    }
}

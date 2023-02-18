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

    pub fn with_secret_refs(mut self, secret_refs: Vec<&SecretVaultRef>) -> Self {
        self.refs = secret_refs.into_iter().cloned().collect();
        self
    }

    pub fn register_secret_refs(&mut self, secret_refs: Vec<&SecretVaultRef>) -> &mut Self {
        self.refs = secret_refs.into_iter().cloned().collect();
        self
    }

    pub fn add_secret_refs(mut self, secret_refs: Vec<&SecretVaultRef>) -> Self {
        self.refs = [secret_refs.into_iter().cloned().collect(), self.refs].concat();
        self
    }

    pub fn add_secret_ref(&mut self, secret_ref: &SecretVaultRef) -> &mut Self {
        self.refs.push(secret_ref.clone());
        self
    }

    pub fn remove_secret_ref(&mut self, key: &SecretVaultKey) -> &mut Self {
        self.refs.retain(|secret_ref| secret_ref.key != *key);
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

        self.compact().await?;

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

    pub async fn refresh_only_not_present(&self) -> SecretVaultResult<&Self> {
        let (existing_refs, missing_refs) = self.store.exists(&self.refs).await;

        if !missing_refs.is_empty() {
            trace!(
                "Refreshing non cached secrets from the source. Existing: {}. Missing: {}",
                existing_refs.len(),
                missing_refs.len()
            );

            let missing_refs: Vec<SecretVaultRef> = missing_refs.into_iter().cloned().collect();

            let mut secrets_map = self.source.get_secrets(&missing_refs).await?;

            for (secret_ref, secret) in secrets_map.drain() {
                self.store.insert(secret_ref, &secret).await?;
            }

            trace!(
                "Secret vault now contains: {} secrets in total",
                self.store.len().await
            );
        } else {
            trace!(
                "No secrets to refresh. All secrets are cached: {}.",
                self.refs.len()
            );
        }

        self.compact().await?;

        Ok(self)
    }

    pub async fn compact(&self) -> SecretVaultResult<()> {
        self.store.compact(&self.refs).await
    }

    pub async fn store_len(&self) -> usize {
        self.store.len().await
    }

    pub fn viewer(&self) -> SecretVaultViewer<E> {
        SecretVaultViewer::new(self.store.clone())
    }

    pub async fn snapshot<SNB, SN>(&self, builder: SNB) -> SecretVaultResult<SN>
    where
        SN: SecretVaultSnapshot,
        SNB: SecretVaultSnapshotBuilder<SN>,
    {
        let refs_allowed_in_snapshot: Vec<SecretVaultRef> = self
            .refs
            .iter()
            .filter(|secret_ref| secret_ref.allow_in_snapshots)
            .cloned()
            .collect();

        let mut secrets: Vec<Secret> = Vec::with_capacity(refs_allowed_in_snapshot.len());

        for secret_ref in refs_allowed_in_snapshot {
            if let Some(secret) = self.store.get_secret(&secret_ref.key).await? {
                secrets.push(secret);
            }
        }

        Ok(builder.build_snapshot(secrets))
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
        self.store.get_secret(&secret_ref.key).await
    }
}

#[cfg(test)]
mod tests {
    use crate::source_tests::*;
    use crate::*;
    use chrono::Utc;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use secret_vault_value::SecretValue;

    #[tokio::test]
    async fn refresh_vault_test() {
        let mut runner = TestRunner::default();
        let mock_secrets_store = generate_mock_secrets_source("default".into())
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let mut vault = SecretVaultBuilder::with_source(mock_secrets_store.clone())
            .build()
            .unwrap();

        vault
            .register_secret_refs(mock_secrets_store.keys().iter().collect())
            .refresh()
            .await
            .unwrap();

        for secret_ref in mock_secrets_store.keys() {
            assert_eq!(
                vault
                    .get_secret_by_ref(&secret_ref)
                    .await
                    .unwrap()
                    .map(|secret| secret.value)
                    .as_ref(),
                mock_secrets_store.get(&secret_ref).as_ref()
            )
        }
    }

    #[tokio::test]
    async fn refresh_only_non_present() {
        let mut runner = TestRunner::default();
        let mut mock_secrets_store = generate_mock_secrets_source("default".into())
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let mut vault = SecretVaultBuilder::with_source(mock_secrets_store.clone())
            .build()
            .unwrap()
            .with_secret_refs(mock_secrets_store.keys().iter().collect());

        vault.refresh().await.unwrap();

        let cached_at = Utc::now();

        let new_secret_ref =
            SecretVaultRef::new("new_secret".into()).with_namespace("default".into());
        vault.add_secret_ref(&new_secret_ref);
        mock_secrets_store.add(
            new_secret_ref.clone(),
            SecretValue::new("new_secret_value".into()),
        );

        vault.refresh_only_not_present().await.unwrap();

        for secret_ref in mock_secrets_store.keys() {
            let ts = vault
                .get_secret_by_ref(&secret_ref)
                .await
                .unwrap()
                .map(|secret| secret.metadata.cached_at)
                .as_ref()
                .unwrap()
                .timestamp();
            if secret_ref.key != new_secret_ref.key {
                assert!(ts <= cached_at.timestamp())
            } else {
                assert!(ts >= cached_at.timestamp())
            }
        }
    }
}

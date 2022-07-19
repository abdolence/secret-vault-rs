use crate::vault_store::SecretVaultStoreRef;
use crate::SecretVaultResult;
use async_trait::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;

#[async_trait]
pub trait SecretsSource {
    async fn get_secrets(
        &self,
        references: Vec<SecretVaultStoreRef>,
    ) -> SecretVaultResult<HashMap<SecretVaultStoreRef, SecretValue>>;
}

pub struct MultipleSecretsSources {
    sources: Vec<Box<dyn SecretsSource + Send + Sync>>,
}

impl MultipleSecretsSources {
    pub fn new(sources: Vec<Box<dyn SecretsSource + Send + Sync>>) -> Self {
        Self { sources }
    }
}

#[async_trait]
impl SecretsSource for MultipleSecretsSources {
    async fn get_secrets(
        &self,
        references: Vec<SecretVaultStoreRef>,
    ) -> SecretVaultResult<HashMap<SecretVaultStoreRef, SecretValue>> {
        let mut result_map: HashMap<SecretVaultStoreRef, SecretValue> = HashMap::new();
        for source in self.sources.iter() {
            let mut source_secrets = source.get_secrets(references.clone()).await?;
            for (secret_ref, secret_value) in source_secrets.drain() {
                result_map.insert(secret_ref, secret_value);
            }
        }

        Ok(result_map)
    }
}

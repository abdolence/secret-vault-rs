use crate::{SecretVaultRef, SecretVaultResult};
use async_trait::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;

#[async_trait]
pub trait SecretsSource {

    fn name(&self) -> String;

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, SecretValue>>;
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

    fn name(&self) -> String {
        self.sources.iter().map(|source| source.name()).collect::<Vec<String>>().join(", ")
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, SecretValue>> {
        let mut result_map: HashMap<SecretVaultRef, SecretValue> = HashMap::new();
        for source in self.sources.iter() {
            let mut source_secrets = source.get_secrets(references).await?;
            for (secret_ref, secret_value) in source_secrets.drain() {
                result_map.insert(secret_ref, secret_value);
            }
        }

        Ok(result_map)
    }
}

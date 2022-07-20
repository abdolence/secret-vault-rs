use crate::*;
use async_trait::*;
use std::collections::HashMap;

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
        self.sources
            .iter()
            .map(|source| source.name())
            .collect::<Vec<String>>()
            .join(", ")
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();
        for source in self.sources.iter() {
            let mut source_secrets = source.get_secrets(references).await?;
            for (secret_ref, secret) in source_secrets.drain() {
                result_map.insert(secret_ref, secret);
            }
        }

        Ok(result_map)
    }
}

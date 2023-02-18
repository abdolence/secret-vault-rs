use crate::*;
use async_trait::*;
use rvstruct::ValueStruct;
use std::collections::HashMap;

pub struct MultipleSecretsSources {
    sources: HashMap<SecretNamespace, Box<dyn SecretsSource + Send + Sync>>,
}

impl MultipleSecretsSources {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    pub fn add_source<S>(mut self, namespace: &SecretNamespace, source: S) -> Self
    where
        S: SecretsSource + Send + Sync + 'static,
    {
        self.sources.insert(namespace.clone(), Box::new(source));
        self
    }

    #[deprecated(
        since = "1.1.7",
        note = "Use add_source to make it obvious it adds a new source, not replace it as other with_ functions do. This will be removed in next releases"
    )]
    pub fn with_source<S>(mut self, namespace: &SecretNamespace, source: S) -> Self
    where
        S: SecretsSource + Send + Sync + 'static,
    {
        self.sources.insert(namespace.clone(), Box::new(source));
        self
    }
}

#[async_trait]
impl SecretsSource for MultipleSecretsSources {
    fn name(&self) -> String {
        self.sources
            .iter()
            .map(|(namespace, source)| format!("{}:{}", namespace.value(), source.name()))
            .collect::<Vec<String>>()
            .join(", ")
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();
        for (namespace, source) in self.sources.iter() {
            let source_references: Vec<SecretVaultRef> = references
                .iter()
                .filter(|reference| {
                    reference
                        .key
                        .namespace
                        .iter()
                        .any(|ref_namespace| *ref_namespace == *namespace)
                })
                .cloned()
                .collect();

            let mut source_secrets = source.get_secrets(&source_references).await?;
            for (secret_ref, secret) in source_secrets.drain() {
                result_map.insert(secret_ref, secret);
            }
        }

        Ok(result_map)
    }
}

#[cfg(test)]
mod tests {
    use crate::source_tests::*;
    use crate::*;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rvstruct::ValueStruct;

    #[tokio::test]
    async fn multiple_sources_test() {
        let mut runner = TestRunner::default();

        let mock_secrets_store1 = generate_mock_secrets_source("mock1".into())
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let mock_secrets_store2 = generate_mock_secrets_source("mock2".into())
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let mut vault = SecretVaultBuilder::with_source(
            MultipleSecretsSources::new()
                .add_source(&"mock1".into(), mock_secrets_store1.clone())
                .add_source(&"mock2".into(), mock_secrets_store2.clone()),
        )
        .build()
        .unwrap();

        fn value_refs_with_namespaces(
            namespace: &str,
            source: &MockSecretsSource,
        ) -> Vec<SecretVaultRef> {
            source
                .keys()
                .into_iter()
                .map(|reference| reference.clone().with_namespace(namespace.into()))
                .collect()
        }

        let mock_secrets1: Vec<SecretVaultRef> =
            value_refs_with_namespaces("mock1", &mock_secrets_store1);
        let mock_secrets2: Vec<SecretVaultRef> =
            value_refs_with_namespaces("mock2", &mock_secrets_store2);
        let all_mock_secrets = [mock_secrets1, mock_secrets2].concat();

        vault
            .register_secret_refs(all_mock_secrets.iter().collect())
            .refresh()
            .await
            .unwrap();

        for secret_ref in all_mock_secrets {
            let test_value =
                if secret_ref.key.namespace.as_ref().unwrap().value().as_str() == "mock1" {
                    mock_secrets_store1.get(&secret_ref)
                } else {
                    mock_secrets_store2.get(&secret_ref)
                };

            assert_eq!(
                vault
                    .get_secret_by_ref(&secret_ref)
                    .await
                    .unwrap()
                    .map(|secret| secret.value)
                    .as_ref(),
                test_value.as_ref()
            )
        }
    }
}

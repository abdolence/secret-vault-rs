use crate::errors::*;
use crate::*;
use async_trait::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MockSecretsSource {
    pub secrets: HashMap<SecretVaultRef, SecretValue>,
}

impl MockSecretsSource {
    pub fn new(secrets: Vec<(SecretVaultRef, SecretValue)>) -> Self {
        Self {
            secrets: secrets.into_iter().collect(),
        }
    }
}

#[async_trait]
impl SecretsSource for MockSecretsSource {
    fn name(&self) -> String {
        "MockSecretsSource".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, SecretValue>> {
        let mut result_map: HashMap<SecretVaultRef, SecretValue> = HashMap::new();

        for secret_ref in references {
            match self.secrets.get(secret_ref) {
                Some(secret_value) => {
                    result_map.insert(secret_ref.clone(), secret_value.clone());
                }
                None if secret_ref.required => {
                    return Err(SecretVaultError::DataNotFoundError(
                        SecretVaultDataNotFoundError::new(
                            SecretVaultErrorPublicGenericDetails::new("ENV_NOT_FOUND".into()),
                            format!(
                                "Secret is required but not found in environment variables {:?}",
                                secret_ref.secret_name
                            ),
                        ),
                    ));
                }
                None => {}
            }
        }

        Ok(result_map)
    }
}

#[cfg(test)]
pub mod source_tests {
    use crate::*;
    use proptest::prelude::*;
    use secret_vault_value::SecretValue;

    pub fn generate_secret_value() -> BoxedStrategy<SecretValue> {
        ("[a-zA-Z0-9]*")
            .prop_map(|(mock_secret_str)| SecretValue::new(mock_secret_str.as_bytes().to_vec()))
            .boxed()
    }

    pub fn generate_secret_ref() -> BoxedStrategy<SecretVaultRef> {
        ("[a-zA-Z0-9]*")
            .prop_map(|(mock_secret_name)| SecretVaultRef::new(mock_secret_name.into()))
            .boxed()
    }

    pub fn generate_mock_secrets_source() -> BoxedStrategy<MockSecretsSource> {
        prop::collection::vec(
            generate_secret_ref().prop_flat_map(move |secret_ref| {
                generate_secret_value()
                    .prop_map(move |secret_value| (secret_ref.clone(), secret_value))
            }),
            1..100,
        )
        .prop_map(|vec| MockSecretsSource::new(vec))
        .boxed()
    }
}

use crate::errors::*;
use crate::*;
use async_trait::*;
use rvstruct::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;
use tracing::*;

#[derive(Debug)]
pub struct InsecureEnvSource;

impl InsecureEnvSource {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl SecretsSource for InsecureEnvSource {
    fn name(&self) -> String {
        "InsecureEnvSource".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            let env_secret_name: String = format!(
                "{}{}",
                secret_ref.secret_name.value(),
                secret_ref
                    .secret_version
                    .as_ref()
                    .map(|sv| { format!("_V{}", sv.value()) })
                    .unwrap_or_else(|| "".to_string())
            );

            trace!(
                "Loading a secret from environment variable: {}",
                &env_secret_name
            );
            match std::env::var_os(env_secret_name.clone())
                .or_else(|| std::env::var_os(env_secret_name.to_uppercase()))
                .as_ref()
                .and_then(|env| env.to_str())
            {
                Some(env) => {
                    let secret_value = SecretValue::from(env);
                    result_map.insert(
                        secret_ref.clone(),
                        Secret::new(secret_value, SecretMetadata::new(secret_ref.clone().into())),
                    );
                }
                None if secret_ref.required => {
                    return Err(SecretVaultError::DataNotFoundError(
                        SecretVaultDataNotFoundError::new(
                            SecretVaultErrorPublicGenericDetails::new("ENV_NOT_FOUND".into()),
                            format!(
                                "Secret is required but not found in environment variables {}",
                                &env_secret_name
                            ),
                        ),
                    ));
                }
                None => {
                    debug!("Secret or secret version {} doesn't exist and since it is not required it is skipped",env_secret_name);
                }
            }
        }

        Ok(result_map)
    }
}

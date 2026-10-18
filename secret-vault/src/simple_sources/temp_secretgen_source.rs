use crate::errors::*;
use crate::*;
use async_trait::*;
use rsb_derive::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;
use tracing::*;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct TempSecretOptions {
    pub key_len: usize,

    #[default = "false"]
    pub regenerate_on_refresh: bool,

    #[default = "true"]
    pub printable: bool,
}

impl TempSecretOptions {
    fn generate_value(&self) -> SecretVaultResult<SecretValue> {
        let effective_key_len = if self.printable {
            self.key_len / 2
        } else {
            self.key_len
        };

        let mut random = SecretValue::new(vec![0; effective_key_len]);
        getrandom::fill(random.ref_sensitive_value_mut()).map_err(|e| {
            SecretVaultError::SecretsSourceError(
                SecretsSourceError::new(
                    SecretVaultErrorPublicGenericDetails::new("RANDOM_GENERATOR".into()),
                    format!("Unable to generate a random secret: {e}"),
                )
                .with_root_cause(Box::new(e)),
            )
        })?;

        if self.printable {
            Ok(SecretValue::from(hex::encode(random.ref_sensitive_value())))
        } else {
            Ok(random)
        }
    }
}

#[derive(Debug, Clone)]
pub struct TempSecretGenSourceOptions {
    registered_secrets: HashMap<SecretVaultKey, TempSecretOptions>,
}

impl TempSecretGenSourceOptions {
    pub fn new() -> Self {
        Self {
            registered_secrets: HashMap::new(),
        }
    }

    pub fn add_secret_generator(
        mut self,
        key: &SecretVaultKey,
        options: TempSecretOptions,
    ) -> Self {
        self.registered_secrets.insert(key.clone(), options);
        self
    }
}

#[derive(Debug)]
pub struct TempSecretGenSource {
    options: TempSecretGenSourceOptions,
    generated_secrets: HashMap<SecretVaultKey, SecretValue>,
}

impl TempSecretGenSource {
    pub fn with_options(options: TempSecretGenSourceOptions) -> SecretVaultResult<Self> {
        let secrets_to_pregen: Vec<(&SecretVaultKey, &TempSecretOptions)> = options
            .registered_secrets
            .iter()
            .filter(|(_, options)| !options.regenerate_on_refresh)
            .collect();

        let mut generated_secrets = HashMap::new();

        for (key, options) in secrets_to_pregen {
            debug!("Pre-generating a new secret value for {:?}", key);
            generated_secrets.insert(key.clone(), options.generate_value()?);
        }

        Ok(Self {
            options,
            generated_secrets,
        })
    }
}

#[async_trait]
impl SecretsSource for TempSecretGenSource {
    fn name(&self) -> String {
        "TempSecretGenSource".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            match self.options.registered_secrets.get(&secret_ref.key) {
                Some(secret_options) => {
                    let secret_value = match self.generated_secrets.get(&secret_ref.key) {
                        Some(secret_value) => secret_value.clone(),
                        None => {
                            debug!("Generating a new secret value for {:?}", secret_ref.key);
                            secret_options.generate_value()?
                        }
                    };

                    result_map.insert(
                        secret_ref.clone(),
                        Secret::new(secret_value, SecretMetadata::create_from_ref(secret_ref)),
                    );
                }
                None if secret_ref.required => {
                    return Err(SecretVaultError::DataNotFoundError(
                        SecretVaultDataNotFoundError::new(
                            SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                            format!(
                                "Secret is required but not found in registered secrets {:?}",
                                secret_ref.key
                            ),
                        ),
                    ))
                }
                None => {
                    debug!("Secret or secret version {:?} doesn't exist and since it is not required it is skipped",secret_ref.key);
                }
            }
        }

        Ok(result_map)
    }
}

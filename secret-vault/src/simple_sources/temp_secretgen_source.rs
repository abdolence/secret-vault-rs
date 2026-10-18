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
    fn generate_value(&self, backend: AeadBackend) -> SecretVaultResult<SecretValue> {
        let random_len = if self.printable {
            self.key_len.div_ceil(2)
        } else {
            self.key_len
        };

        let random = backend.generate_random_bytes(random_len).map_err(|e| {
            SecretVaultError::SecretsSourceError(
                SecretsSourceError::new(
                    SecretVaultErrorPublicGenericDetails::new(e.code().to_string()),
                    format!("Unable to generate a random secret: {e}"),
                )
                .with_root_cause(Box::new(e)),
            )
        })?;

        if self.printable {
            let mut printable = hex::encode(random.ref_sensitive_value());
            printable.truncate(self.key_len);
            Ok(SecretValue::from(printable))
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

/// Generates the registered secrets from the CSPRNG of an AEAD backend. `AeadBackend::AwsLc` in a
/// build with `aws-lc-fips` draws them from the DRBG of the FIPS module.
#[derive(Debug)]
pub struct TempSecretGenSource {
    options: TempSecretGenSourceOptions,
    backend: AeadBackend,
    generated_secrets: HashMap<SecretVaultKey, SecretValue>,
}

impl TempSecretGenSource {
    /// Generates the secrets that are not regenerated on refresh now, and the others on each
    /// refresh, from the CSPRNG of `backend`.
    ///
    /// # Errors
    ///
    /// A `SecretsSourceError` with the code `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn with_options(
        options: TempSecretGenSourceOptions,
        backend: AeadBackend,
    ) -> SecretVaultResult<Self> {
        let secrets_to_pregen: Vec<(&SecretVaultKey, &TempSecretOptions)> = options
            .registered_secrets
            .iter()
            .filter(|(_, options)| !options.regenerate_on_refresh)
            .collect();

        let mut generated_secrets = HashMap::new();

        for (key, options) in secrets_to_pregen {
            debug!("Pre-generating a new secret value for {:?}", key);
            generated_secrets.insert(key.clone(), options.generate_value(backend)?);
        }

        Ok(Self {
            options,
            backend,
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
                            secret_options.generate_value(self.backend)?
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

#[cfg(test)]
mod tests {
    use super::*;

    static PRINTABLE_SECRET: SecretVaultRef =
        SecretVaultRef::new(SecretName::from_static("printable-secret"));
    static RAW_SECRET: SecretVaultRef = SecretVaultRef::new(SecretName::from_static("raw-secret"));

    #[tokio::test]
    async fn generated_secrets_have_the_requested_length() -> SecretVaultResult<()> {
        let source = TempSecretGenSource::with_options(
            TempSecretGenSourceOptions::new()
                .add_secret_generator(&PRINTABLE_SECRET.key, TempSecretOptions::new(33))
                .add_secret_generator(
                    &RAW_SECRET.key,
                    TempSecretOptions::new(64)
                        .with_printable(false)
                        .with_regenerate_on_refresh(true),
                ),
            TEST_BACKEND,
        )?;

        let secrets = source
            .get_secrets(&[PRINTABLE_SECRET.clone(), RAW_SECRET.clone()])
            .await?;

        assert_eq!(
            secrets[&PRINTABLE_SECRET].value.ref_sensitive_value().len(),
            33
        );
        assert_eq!(secrets[&RAW_SECRET].value.ref_sensitive_value().len(), 64);
        Ok(())
    }
}

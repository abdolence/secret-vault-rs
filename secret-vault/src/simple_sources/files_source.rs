use crate::errors::*;
use crate::*;
use async_trait::*;
use rsb_derive::*;
use rvstruct::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;
use std::path::Path;
use tracing::*;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct FilesSourceOptions {
    pub root_path: Option<Box<Path>>,
}

#[derive(Debug)]
pub struct FilesSource {
    options: FilesSourceOptions,
}

impl FilesSource {
    pub fn new() -> Self {
        Self::with_options(FilesSourceOptions::new())
    }

    pub fn with_options(options: FilesSourceOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl SecretsSource for FilesSource {
    fn name(&self) -> String {
        "FilesSource".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            let secret_file_name: String = format!(
                "{}{}{}",
                self.options
                    .root_path
                    .as_ref()
                    .and_then(|rp| rp.to_str())
                    .map(|path| format!("{path}/"))
                    .unwrap_or_else(|| "".to_string()),
                secret_ref.key.secret_name.value(),
                secret_ref
                    .key
                    .secret_version
                    .as_ref()
                    .map(|sv| { format!("_v{}", sv.value()) })
                    .unwrap_or_else(|| "".to_string())
            );

            trace!("Loading a secret file from: {}", &secret_file_name);
            match std::fs::read(Path::new(secret_file_name.as_str())) {
                Ok(file_content) => {
                    let secret_value = SecretValue::from(file_content);
                    let metadata = SecretMetadata::create_from_ref(secret_ref);

                    result_map.insert(secret_ref.clone(), Secret::new(secret_value, metadata));
                }
                Err(err) if secret_ref.required => {
                    return Err(SecretVaultError::DataNotFoundError(
                        SecretVaultDataNotFoundError::new(
                            SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                            format!(
                                "Secret is required but corresponding file is not available `{}`: {}",
                                &secret_file_name,
                                err
                            ),
                        ),
                    ));
                }
                Err(err) => {
                    debug!("Secret or secret version doesn't exist at {} and since it is not required it is skipped: {}",secret_file_name, err);
                }
            }
        }

        Ok(result_map)
    }
}

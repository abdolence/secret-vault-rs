use crate::errors::*;
use crate::*;
use async_trait::*;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use std::collections::HashMap;
use tracing::*;

#[derive(Debug, Clone)]
pub struct AmazonSecretManagerSource {
    account_id: String,
    client: aws_sdk_secretsmanager::Client,
    aws_region: aws_sdk_secretsmanager::Region,
}

impl AmazonSecretManagerSource {
    pub async fn new(
        account_id: &String,
        region: Option<aws_sdk_secretsmanager::Region>,
    ) -> SecretVaultResult<Self> {
        let shared_config = aws_config::load_from_env().await;
        let effective_region = region.or(shared_config.region().cloned()).ok_or(
            SecretVaultError::InvalidParametersError(SecretVaultInvalidParametersError::new(
                SecretVaultInvalidParametersPublicDetails::new(
                    "region".into(),
                    "AWS region must be specified or available in the AWS shared config".into(),
                ),
            )),
        )?;

        let client = aws_sdk_secretsmanager::Client::new(&shared_config);
        Ok(AmazonSecretManagerSource {
            account_id: account_id.clone(),
            client,
            aws_region: effective_region,
        })
    }
}

#[async_trait]
impl SecretsSource for AmazonSecretManagerSource {
    fn name(&self) -> String {
        "AmazonSecretManager".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            let aws_secret_arn = format!(
                "arn:aws:secretsmanager:{}:{}:secret:{}",
                self.aws_region,
                self.account_id,
                secret_ref.secret_name.value()
            );

            match self
                .client
                .get_secret_value()
                .secret_id(aws_secret_arn.clone())
                .send()
                .await
            {
                Ok(aws_secret) => {
                    let maybe_secret_value =
                        aws_secret
                            .secret_string
                            .map(SecretValue::from)
                            .or(aws_secret
                                .secret_binary
                                .map(|secret_binary| SecretValue::new(secret_binary.into_inner())));

                    if let Some(secret_value) = maybe_secret_value {
                        let metadata = SecretMetadata::new()
                            .opt_version(aws_secret.version_id.map(|v| v.into()));
                        result_map.insert(secret_ref.clone(), Secret::new(secret_value, metadata));
                    } else if secret_ref.required {
                        return Err(SecretVaultError::DataNotFoundError(
                            SecretVaultDataNotFoundError::new(
                                SecretVaultErrorPublicGenericDetails::new("SECRET_PAYLOAD".into()),
                                format!(
                                    "Secret is required but payload is not found for {}",
                                    aws_secret_arn
                                ),
                            ),
                        ));
                    }
                }
                Err(err) => {
                    let err_string = err.to_string();
                    if err_string.contains("ResourceNotFoundException") {
                        if secret_ref.required {
                            return Err(SecretVaultError::DataNotFoundError(
                                SecretVaultDataNotFoundError::new(
                                    SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                                    format!(
                                        "Secret is required but not found in environment variables {:?}",
                                        secret_ref.secret_name
                                    ),
                                ),
                            ));
                        } else {
                            debug!("Secret or secret version {} doesn't exist and since it is not required it is skipped",aws_secret_arn);
                        }
                    } else {
                        error!(
                            "Unable to read secret or secret version {}: {}.",
                            aws_secret_arn, err
                        );
                        return Err(SecretVaultError::SecretsSourceError(
                            SecretsSourceError::new(
                                SecretVaultErrorPublicGenericDetails::new("AWS_ERROR".into()),
                                format!("AWS error {:?}: {}", secret_ref.secret_name, err_string),
                            ),
                        ));
                    }
                }
            }
        }

        Ok(result_map)
    }
}

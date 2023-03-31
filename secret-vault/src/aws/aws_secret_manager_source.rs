use crate::errors::*;
use crate::*;
use async_trait::*;
use aws_sdk_secretsmanager::error::SdkError;
use aws_smithy_types_convert::date_time::DateTimeExt;
use rsb_derive::*;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use std::collections::HashMap;
use tracing::*;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AwsSecretManagerSourceOptions {
    pub account_id: String,
    pub region: Option<aws_sdk_secretsmanager::config::Region>,

    #[default = "false"]
    pub read_metadata: bool,
}

#[derive(Debug, Clone)]
pub struct AwsSecretManagerSource {
    client: aws_sdk_secretsmanager::Client,
    options: AwsSecretManagerSourceOptions,
}

impl AwsSecretManagerSource {
    pub async fn new(account_id: &str) -> SecretVaultResult<Self> {
        Self::with_options(AwsSecretManagerSourceOptions::new(account_id.to_string())).await
    }

    pub async fn with_options(options: AwsSecretManagerSourceOptions) -> SecretVaultResult<Self> {
        let shared_config = aws_config::load_from_env().await;
        let effective_region = options
            .region
            .clone()
            .or_else(|| shared_config.region().cloned())
            .ok_or_else(|| {
                SecretVaultError::InvalidParametersError(SecretVaultInvalidParametersError::new(
                    SecretVaultInvalidParametersPublicDetails::new(
                        "region".into(),
                        "AWS region must be specified or available in the AWS shared config".into(),
                    ),
                ))
            })?;

        let client = aws_sdk_secretsmanager::Client::new(&shared_config);
        Ok(AwsSecretManagerSource {
            client,
            options: options.with_region(effective_region),
        })
    }
}

#[async_trait]
impl SecretsSource for AwsSecretManagerSource {
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
                self.options.region.as_ref().unwrap(),
                self.options.account_id,
                secret_ref.key.secret_name.value()
            );

            match self
                .client
                .get_secret_value()
                .secret_id(aws_secret_arn.clone())
                .set_version_stage(
                    secret_ref
                        .key
                        .secret_version
                        .as_ref()
                        .map(|v| v.value().into()),
                )
                .send()
                .await
            {
                Ok(aws_secret) => {
                    let maybe_secret_value =
                        aws_secret.secret_string.map(SecretValue::from).or_else(|| {
                            aws_secret
                                .secret_binary
                                .map(|secret_binary| SecretValue::new(secret_binary.into_inner()))
                        });

                    if let Some(secret_value) = maybe_secret_value {
                        let mut metadata = SecretMetadata::create_from_ref(secret_ref);

                        let maybe_aws_secret = if self.options.read_metadata {
                            Some(
                                self.client
                                    .describe_secret()
                                    .secret_id(aws_secret_arn.clone())
                                    .send()
                                    .await?,
                            )
                        } else {
                            None
                        };

                        if let Some(aws_secret_desc) = maybe_aws_secret {
                            for tag in aws_secret_desc.tags().unwrap_or(&[]) {
                                if let Some(tag_key) = tag.key() {
                                    metadata.add_label(
                                        SecretMetadataLabel::new(tag_key.to_string())
                                            .opt_value(tag.value().map(|s| s.to_string())),
                                    );
                                }
                            }

                            metadata.description =
                                aws_secret_desc.description().map(|s| s.to_string());
                            metadata.created_at = aws_secret_desc
                                .created_date()
                                .and_then(|d| d.to_chrono_utc().ok());
                            metadata.updated_at = aws_secret_desc
                                .last_changed_date()
                                .and_then(|d| d.to_chrono_utc().ok());
                        }

                        result_map.insert(secret_ref.clone(), Secret::new(secret_value, metadata));
                    } else if secret_ref.required {
                        return Err(SecretVaultError::DataNotFoundError(
                            SecretVaultDataNotFoundError::new(
                                SecretVaultErrorPublicGenericDetails::new("SECRET_PAYLOAD".into()),
                                format!(
                                    "Secret is required but payload is not found for {aws_secret_arn}"
                                ),
                            ),
                        ));
                    }
                }
                Err(SdkError::ServiceError(svc_err))
                    if svc_err.err().is_resource_not_found_exception() =>
                {
                    if secret_ref.required {
                        return Err(SecretVaultError::DataNotFoundError(
                                SecretVaultDataNotFoundError::new(
                                    SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                                    format!(
                                        "Secret is required but not found in environment variables {:?}",
                                        secret_ref.key.secret_name
                                    ),
                                ),
                            ));
                    } else {
                        debug!("Secret or secret version {}/{:?} doesn't exist and since it is not required it is skipped",aws_secret_arn, &secret_ref.key.secret_version);
                    }
                }
                Err(err) => {
                    error!(
                        "Unable to read secret or secret version {}/{:?}: {}.",
                        aws_secret_arn, &secret_ref.key.secret_version, err
                    );
                    return Err(SecretVaultError::from(err));
                }
            }
        }

        Ok(result_map)
    }
}

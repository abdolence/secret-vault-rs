use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::*;
use rsb_derive::*;
use rvstruct::ValueStruct;
use std::collections::HashMap;

use crate::errors::*;
use crate::secrets_source::SecretsSource;
use crate::*;
use tracing::*;

use crate::prost_chrono::chrono_time_from_prost;
use async_trait::*;
use gcloud_sdk::google::cloud::secretmanager::v1::{AccessSecretVersionRequest, GetSecretRequest};

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct GcpSecretManagerSourceOptions {
    pub google_project_id: String,

    #[default = "false"]
    pub read_metadata: bool,
}

pub struct GcpSecretManagerSource {
    secret_manager_client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
    options: GcpSecretManagerSourceOptions,
}

impl GcpSecretManagerSource {
    pub async fn new(google_project_id: &str) -> SecretVaultResult<Self> {
        Self::with_options(GcpSecretManagerSourceOptions::new(
            google_project_id.to_string(),
        ))
        .await
    }

    pub async fn with_options(options: GcpSecretManagerSourceOptions) -> SecretVaultResult<Self> {
        let client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                SecretManagerServiceClient::new,
                "https://secretmanager.googleapis.com",
                None,
            )
            .await
            .map_err(SecretVaultError::from)?;

        Ok(Self {
            secret_manager_client: client,
            options,
        })
    }
}

#[async_trait]
impl SecretsSource for GcpSecretManagerSource {
    fn name(&self) -> String {
        "GoogleSecretManager".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();
        for secret_ref in references {
            let gcp_secret_version = secret_ref
                .key
                .secret_version
                .as_ref()
                .map(|v| v.value().clone())
                .unwrap_or_else(|| "latest".to_string());

            let gcp_secret_version_path = format!(
                "projects/{}/secrets/{}/versions/{}",
                self.options.google_project_id,
                secret_ref.key.secret_name.value(),
                &gcp_secret_version
            );

            trace!("Reading GCP secret: {}", gcp_secret_version_path);
            let get_secret_response = self
                .secret_manager_client
                .get()
                .access_secret_version(tonic::Request::new(AccessSecretVersionRequest {
                    name: gcp_secret_version_path.clone(),
                    ..Default::default()
                }))
                .await
                .map_err(SecretVaultError::from);

            match get_secret_response {
                Ok(response) => {
                    let secret_response = response.into_inner();
                    if let Some(payload) = secret_response.payload {
                        let maybe_gcp_secret = if self.options.read_metadata {
                            let gcp_secret_path = format!(
                                "projects/{}/secrets/{}",
                                self.options.google_project_id,
                                secret_ref.key.secret_name.value()
                            );

                            Some(
                                self.secret_manager_client
                                    .get()
                                    .get_secret(tonic::Request::new(GetSecretRequest {
                                        name: gcp_secret_path.clone(),
                                    }))
                                    .await
                                    .map_err(SecretVaultError::from)?
                                    .into_inner(),
                            )
                        } else {
                            None
                        };

                        let mut metadata = SecretMetadata::create_from_ref(secret_ref)
                            .with_version(gcp_secret_version.into());

                        if let Some(gcp_secret) = maybe_gcp_secret {
                            if let Some(expiration) = gcp_secret.expiration {
                                metadata.expiration(from_google_expiration(expiration)?);
                            }

                            for (k, v) in gcp_secret.labels {
                                metadata.add_label(SecretMetadataLabel::new(k).with_value(v));
                            }

                            for (k, v) in gcp_secret.annotations {
                                metadata
                                    .add_annotation(SecretMetadataAnnotation::new(k).with_value(v));
                            }

                            metadata.created_at =
                                gcp_secret.create_time.and_then(chrono_time_from_prost);
                        }

                        result_map.insert(secret_ref.clone(), Secret::new(payload.data, metadata));
                    } else if secret_ref.required {
                        return Err(SecretVaultError::DataNotFoundError(
                            SecretVaultDataNotFoundError::new(
                                SecretVaultErrorPublicGenericDetails::new("SECRET_PAYLOAD".into()),
                                format!(
                                    "Secret is required but payload is not found for {gcp_secret_version_path}"
                                ),
                            ),
                        ));
                    }
                }
                Err(err) => match err {
                    SecretVaultError::DataNotFoundError(_) if !secret_ref.required => {
                        debug!("Secret or secret version {gcp_secret_version_path} doesn't exist and since it is not required it is skipped");
                    }
                    _ => {
                        error!(
                            "Unable to read secret or secret version {gcp_secret_version_path}: {err}."
                        );
                        return Err(err);
                    }
                },
            }
        }
        Ok(result_map)
    }
}

fn from_google_expiration(
    gcp_expiration: gcloud_sdk::google::cloud::secretmanager::v1::secret::Expiration,
) -> SecretVaultResult<SecretExpiration> {
    match gcp_expiration {
        gcloud_sdk::google::cloud::secretmanager::v1::secret::Expiration::ExpireTime(ts) => {
            if let Some(dt) = crate::prost_chrono::chrono_time_from_prost(ts) {
                Ok(SecretExpiration::ExpireTime(dt))
            } else {
                Err(SecretVaultError::InvalidParametersError(
                    SecretVaultInvalidParametersError::new(
                        SecretVaultInvalidParametersPublicDetails::new(
                            "expiration".into(),
                            "Secret expire time conversion error".into(),
                        ),
                    ),
                ))
            }
        }
        gcloud_sdk::google::cloud::secretmanager::v1::secret::Expiration::Ttl(ts) => Ok(
            SecretExpiration::Ttl(crate::prost_chrono::chrono_duration_from_prost(ts)),
        ),
    }
}

use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::*;
use rvstruct::ValueStruct;
use std::collections::HashMap;

use crate::errors::*;
use crate::secrets_source::SecretsSource;
use crate::*;
use tracing::*;

use async_trait::*;
use gcloud_sdk::google::cloud::secretmanager::v1::AccessSecretVersionRequest;

pub struct GcpSecretManagerSource {
    secret_manager_client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
    google_project_id: String,
}

impl GcpSecretManagerSource {
    pub async fn new(google_project_id: &str) -> SecretVaultResult<Self> {
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
            google_project_id: google_project_id.to_string(),
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

            let gcp_secret_path = format!(
                "projects/{}/secrets/{}/versions/{}",
                self.google_project_id,
                secret_ref.key.secret_name.value(),
                &gcp_secret_version
            );

            trace!("Reading GCP secret: {}", gcp_secret_path);
            let get_secret_response = self
                .secret_manager_client
                .get()
                .access_secret_version(tonic::Request::new(AccessSecretVersionRequest {
                    name: gcp_secret_path.clone(),
                    ..Default::default()
                }))
                .await
                .map_err(SecretVaultError::from);

            match get_secret_response {
                Ok(response) => {
                    let secret_response = response.into_inner();
                    if let Some(payload) = secret_response.payload {
                        let metadata = SecretMetadata::create_from_ref(secret_ref)
                            .with_version(gcp_secret_version.into());

                        result_map.insert(secret_ref.clone(), Secret::new(payload.data, metadata));
                    } else if secret_ref.required {
                        return Err(SecretVaultError::DataNotFoundError(
                            SecretVaultDataNotFoundError::new(
                                SecretVaultErrorPublicGenericDetails::new("SECRET_PAYLOAD".into()),
                                format!(
                                    "Secret is required but payload is not found for {}",
                                    gcp_secret_path
                                ),
                            ),
                        ));
                    }
                }
                Err(err) => match err {
                    SecretVaultError::DataNotFoundError(_) if !secret_ref.required => {
                        debug!("Secret or secret version {} doesn't exist and since it is not required it is skipped",gcp_secret_path);
                    }
                    _ => {
                        error!(
                            "Unable to read secret or secret version {}: {}.",
                            gcp_secret_path, err
                        );
                        return Err(err);
                    }
                },
            }
        }
        Ok(result_map)
    }
}

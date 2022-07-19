use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::*;
use std::collections::HashMap;
use rvstruct::ValueStruct;

use crate::errors::*;
use crate::secrets_source::SecretsSource;
use crate::vault_store::SecretVaultStoreRef;
use crate::{SecretVault, SecretVaultResult, SecretVaultStoreValueAllocator, SecretVaultStoreValueNoAllocator};
use secret_vault_value::SecretValue;

use async_trait::*;
use gcloud_sdk::google::cloud::secretmanager::v1::AccessSecretVersionRequest;
use crate::encryption::{EncryptedSecretValue, NoEncryption, SecretVaultEncryption};

pub struct GoogleSecretManagerSource {
    secret_manager_client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
    google_project_id: String,
}

impl GoogleSecretManagerSource {
    pub async fn new(google_project_id: &String) -> SecretVaultResult<Self> {
        let client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                SecretManagerServiceClient::new,
                "https://secretmanager.googleapis.com",
                None,
            )
            .await
            .map_err(|e| SecretVaultError::from(e))?;

        Ok(Self {
            secret_manager_client: client,
            google_project_id: google_project_id.clone(),
        })
    }
}

#[async_trait]
impl SecretsSource for GoogleSecretManagerSource {
    async fn get_secrets(
        &self,
        mut references: Vec<SecretVaultStoreRef>,
    ) -> SecretVaultResult<HashMap<SecretVaultStoreRef, SecretValue>> {
        let mut result_map: HashMap<SecretVaultStoreRef, SecretValue> = HashMap::new();
        for secret_ref in references.drain(0..) {
            let response = self.secret_manager_client
                .get()
                .access_secret_version(tonic::Request::new(AccessSecretVersionRequest {
                    name: format!(
                        "projects/{}/secrets/{}/versions/{}",
                        self.google_project_id,
                        secret_ref.secret_name.value(),
                        secret_ref.secret_version.as_ref().map(|v| v.value().clone()).unwrap_or_else(|| "latest".to_string())
                    ),
                    ..Default::default()
                }))
                .await
                .map_err(|e| SecretVaultError::from(e))?;

            let secret_response = response.into_inner();
            if let Some(payload) =  secret_response.payload {
                result_map.insert(secret_ref, payload.data);
            }
        }
        Ok(result_map)
    }
}

pub type GoogleEncryptedSecretVault<R,AR,E> = SecretVault<GoogleSecretManagerSource, R, AR, E>;
pub type GoogleSecretVault = GoogleEncryptedSecretVault<EncryptedSecretValue, SecretVaultStoreValueNoAllocator, NoEncryption>;


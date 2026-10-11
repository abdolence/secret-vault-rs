use std::collections::HashMap;

use async_trait::async_trait;
use jiff::Timestamp;
use rsb_derive::Builder;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use tracing::*;
use vaultrs::api::kv2::requests::ReadSecretRequest;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

use crate::errors::*;
use crate::*;

/// Options for [`HashiCorpVaultSource`].
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct HashiCorpVaultSourceOptions {
    /// Mount path of the KV secrets engine v2 the secrets are read from.
    #[default = "\"secret\".into()"]
    pub mount: String,

    /// Read the KV v2 custom metadata into the secret labels.
    #[default = "false"]
    pub read_metadata: bool,
}

/// Reads secrets from the KV secrets engine v2 of a HashiCorp Vault server.
///
/// The secret name is the path of the secret inside the mount, and the secret
/// version is the KV v2 version number. The secret value is the `data` object
/// of that version, serialized as JSON.
pub struct HashiCorpVaultSource {
    client: VaultClient,
    options: HashiCorpVaultSourceOptions,
}

impl HashiCorpVaultSource {
    /// Connects with the default options, using the address and token from
    /// the `VAULT_ADDR` and `VAULT_TOKEN` environment variables.
    pub fn new() -> SecretVaultResult<Self> {
        Self::with_options(HashiCorpVaultSourceOptions::new())
    }

    /// Connects using the address and token from the `VAULT_ADDR` and
    /// `VAULT_TOKEN` environment variables (and the other `VAULT_*` variables
    /// the `vaultrs` client settings read).
    pub fn with_options(options: HashiCorpVaultSourceOptions) -> SecretVaultResult<Self> {
        let settings = VaultClientSettingsBuilder::default().build().map_err(|e| {
            SecretVaultError::InvalidParametersError(SecretVaultInvalidParametersError::new(
                SecretVaultInvalidParametersPublicDetails::new(
                    "VAULT_ADDR".into(),
                    format!("Unable to configure the Vault client from the environment: {e}"),
                ),
            ))
        })?;
        let client = VaultClient::new(settings)?;
        Ok(Self::with_client(client, options))
    }

    /// Uses a client the caller has already configured and authenticated,
    /// for example after a login with one of the `vaultrs::auth` methods.
    pub fn with_client(client: VaultClient, options: HashiCorpVaultSourceOptions) -> Self {
        Self { client, options }
    }

    fn metadata_from_response(
        &self,
        secret_ref: &SecretVaultRef,
        version_metadata: vaultrs::api::kv2::responses::SecretVersionMetadata,
    ) -> SecretMetadata {
        let mut metadata = SecretMetadata::create_from_ref(secret_ref)
            .with_version(version_metadata.version.to_string().into());

        if self.options.read_metadata {
            let mut custom_metadata: Vec<(String, String)> = version_metadata
                .custom_metadata
                .unwrap_or_default()
                .into_iter()
                .collect();
            custom_metadata.sort();
            for (name, value) in custom_metadata {
                metadata.add_label(SecretMetadataLabel::new(name).with_value(value));
            }

            match version_metadata.created_time.parse::<Timestamp>() {
                Ok(created_at) => metadata.created_at = Some(created_at),
                Err(err) => warn!(
                    created_time = %version_metadata.created_time,
                    %err,
                    "Unable to parse the Vault secret version creation time"
                ),
            }
        }

        metadata
    }
}

#[async_trait]
impl SecretsSource for HashiCorpVaultSource {
    fn name(&self) -> String {
        "HashiCorpVault".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            let secret_path: &str = secret_ref.key.secret_name.value();
            let kv_version = secret_ref
                .key
                .secret_version
                .as_ref()
                .map(|version| {
                    let version: &str = version.value();
                    version.parse::<u64>().map_err(|_| {
                        SecretVaultError::InvalidParametersError(
                            SecretVaultInvalidParametersError::new(
                                SecretVaultInvalidParametersPublicDetails::new(
                                    "secret_version".into(),
                                    format!(
                                        "KV v2 version must be a positive integer, got `{version}` for secret `{secret_path}`"
                                    ),
                                ),
                            ),
                        )
                    })
                })
                .transpose()?;

            let request = ReadSecretRequest::builder()
                .mount(self.options.mount.as_str())
                .path(secret_path)
                .version(kv_version)
                .build()
                .map_err(|e| {
                    SecretVaultError::SystemError(SecretVaultSystemError::new(
                        SecretVaultErrorPublicGenericDetails::new("VAULT_REQUEST_BUILD".into()),
                        format!("Unable to build the Vault read request: {e}"),
                    ))
                })?;

            trace!(
                mount = %self.options.mount,
                path = secret_path,
                ?kv_version,
                "Reading HashiCorp Vault secret"
            );

            match vaultrs::api::exec_with_result(&self.client, request)
                .await
                .map_err(SecretVaultError::from)
            {
                Ok(response) if response.data.is_null() => {
                    if secret_ref.required {
                        return Err(SecretVaultError::DataNotFoundError(
                            SecretVaultDataNotFoundError::new(
                                SecretVaultErrorPublicGenericDetails::new("SECRET_PAYLOAD".into()),
                                format!(
                                    "Secret is required but payload is not found for {}/{secret_path} (version {kv_version:?})",
                                    self.options.mount
                                ),
                            ),
                        ));
                    }
                }
                Ok(response) => {
                    // The intermediate JSON lives in vaultrs and serde_json buffers that
                    // are not zeroized; only the copy kept here is a `SecretValue`.
                    let secret_value =
                        SecretValue::new(serde_json::to_vec(&response.data).map_err(|e| {
                            SecretVaultError::SystemError(SecretVaultSystemError::new(
                                SecretVaultErrorPublicGenericDetails::new(
                                    "VAULT_PAYLOAD_ENCODING".into(),
                                ),
                                format!("Unable to encode the Vault secret data: {e}"),
                            ))
                        })?);
                    let metadata = self.metadata_from_response(secret_ref, response.metadata);
                    result_map.insert(secret_ref.clone(), Secret::new(secret_value, metadata));
                }
                Err(SecretVaultError::DataNotFoundError(_)) if !secret_ref.required => {
                    debug!(
                        mount = %self.options.mount,
                        path = secret_path,
                        ?kv_version,
                        "Secret or secret version doesn't exist and since it is not required it is skipped"
                    );
                }
                Err(err) => {
                    error!(
                        mount = %self.options.mount,
                        path = secret_path,
                        ?kv_version,
                        %err,
                        "Unable to read secret or secret version"
                    );
                    return Err(err);
                }
            }
        }

        Ok(result_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_error_payload_is_absent_from_mapped_error() {
        let secret_payload = "s3cr3t-payload-value";
        let parse_error = serde_json::from_str::<u64>(&format!("\"{secret_payload}\""))
            .expect_err("a JSON string is not a u64");
        assert!(format!("{parse_error}").contains(secret_payload));

        let error = SecretVaultError::from(vaultrs::error::ClientError::RestClientError {
            source: rustify::errors::ClientError::ResponseParseError {
                source: parse_error.into(),
                content: Some(format!(
                    "{{\"data\":{{\"password\":\"{secret_payload}\"}}}}"
                )),
            },
        });

        assert!(!format!("{error}").contains(secret_payload));
        assert!(!format!("{error:?}").contains(secret_payload));
    }
}

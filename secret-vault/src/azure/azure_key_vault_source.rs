use crate::errors::*;
use crate::*;
use async_trait::*;
use azure_core::credentials::TokenCredential;
use azure_core::time::OffsetDateTime;
use azure_security_keyvault_secrets::models::{self, SecretClientGetSecretOptions};
use azure_security_keyvault_secrets::{ResourceExt, SecretClient, SecretClientOptions};
use jiff::Timestamp;
use rsb_derive::*;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::*;

#[derive(Debug, Clone, Builder)]
pub struct AzureKeyVaultSourceOptions {
    /// Vault URL, such as `https://my-vault.vault.azure.net`.
    pub vault_url: String,

    #[default = "false"]
    pub read_metadata: bool,

    /// Client settings passed to the Azure SDK, such as a custom HTTP transport or retry policy.
    pub client_options: Option<SecretClientOptions>,
}

/// Reads secrets from Azure Key Vault.
///
/// Key Vault secret names allow only ASCII letters, digits and `-`, and versions only ASCII
/// letters and digits. A reference outside those sets fails with
/// [`SecretVaultError::InvalidParametersError`] whether or not it is required, since such a
/// secret cannot exist in any vault.
pub struct AzureKeyVaultSource {
    client: SecretClient,
    options: AzureKeyVaultSourceOptions,
}

impl AzureKeyVaultSource {
    /// Connects to the vault at `vault_url` with any Azure credential, for example one from
    /// `azure_identity` (managed identity, Azure CLI, client secret).
    pub fn new(vault_url: &str, credential: Arc<dyn TokenCredential>) -> SecretVaultResult<Self> {
        Self::with_options(
            AzureKeyVaultSourceOptions::new(vault_url.to_string()),
            credential,
        )
    }

    pub fn with_options(
        options: AzureKeyVaultSourceOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> SecretVaultResult<Self> {
        let client = SecretClient::new(
            &options.vault_url,
            credential,
            options.client_options.clone(),
        )?;
        Ok(Self { client, options })
    }

    /// Converts a Key Vault response into a vault secret; `None` when the response has no value.
    fn secret_from_key_vault(
        &self,
        secret_ref: &SecretVaultRef,
        kv_secret: models::Secret,
    ) -> SecretVaultResult<Option<Secret>> {
        let mut metadata = SecretMetadata::create_from_ref(secret_ref);
        match kv_secret.resource_id() {
            Ok(resource_id) => {
                metadata.version = resource_id.version.map(SecretVersion::from);
            }
            Err(err) => {
                warn!(
                    "Unable to read the version of Key Vault secret {:?} from its id: {err}",
                    secret_ref.key.secret_name
                );
            }
        }

        if self.options.read_metadata {
            for (name, value) in kv_secret.tags.into_iter().flatten() {
                metadata.add_label(SecretMetadataLabel::new(name).with_value(value));
            }
            if let Some(attributes) = kv_secret.attributes {
                if let Some(expires) = attributes.expires {
                    metadata
                        .expiration(SecretExpiration::ExpireTime(timestamp_from_azure(expires)?));
                }
                metadata.created_at = attributes.created.map(timestamp_from_azure).transpose()?;
                metadata.updated_at = attributes.updated.map(timestamp_from_azure).transpose()?;
            }
        }

        Ok(kv_secret
            .value
            .map(|value| Secret::new(SecretValue::from(value), metadata)))
    }
}

impl std::fmt::Debug for AzureKeyVaultSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKeyVaultSource")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SecretsSource for AzureKeyVaultSource {
    fn name(&self) -> String {
        "AzureKeyVault".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            let secret_id = KeyVaultSecretId::try_from(&secret_ref.key)?;
            trace!("Reading Azure Key Vault secret: {secret_id}");

            let response = self
                .client
                .get_secret(
                    secret_id.name,
                    Some(SecretClientGetSecretOptions {
                        secret_version: secret_id.version.map(str::to_string),
                        ..Default::default()
                    }),
                )
                .await
                .and_then(|response| response.into_model())
                .map_err(SecretVaultError::from);

            match response {
                Ok(kv_secret) => match self.secret_from_key_vault(secret_ref, kv_secret)? {
                    Some(secret) => {
                        result_map.insert(secret_ref.clone(), secret);
                    }
                    None if secret_ref.required => {
                        return Err(SecretVaultError::DataNotFoundError(
                            SecretVaultDataNotFoundError::new(
                                SecretVaultErrorPublicGenericDetails::new("SECRET_PAYLOAD".into()),
                                format!(
                                    "Secret is required but payload is not found for {secret_id}"
                                ),
                            ),
                        ));
                    }
                    None => {}
                },
                Err(SecretVaultError::DataNotFoundError(_)) if !secret_ref.required => {
                    debug!("Secret or secret version {secret_id} doesn't exist and since it is not required it is skipped");
                }
                Err(err) => {
                    error!("Unable to read secret or secret version {secret_id}: {err}.");
                    return Err(err);
                }
            }
        }

        Ok(result_map)
    }
}

/// A secret name and optional version checked against the Key Vault character sets.
///
/// The SDK substitutes both into the request path without escaping, so a `/` or `?` in either
/// would address a different resource.
struct KeyVaultSecretId<'a> {
    name: &'a str,
    version: Option<&'a str>,
}

impl<'a> TryFrom<&'a SecretVaultKey> for KeyVaultSecretId<'a> {
    type Error = SecretVaultError;

    fn try_from(key: &'a SecretVaultKey) -> Result<Self, Self::Error> {
        let name: &str = key.secret_name.value();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(SecretVaultInvalidParametersError::create(
                "secret_name",
                format!("Azure Key Vault secret names allow only 0-9, a-z, A-Z and -: {name:?}"),
            ));
        }

        let version: Option<&str> = key.secret_version.as_ref().map(|v| &**v.value());
        if let Some(version) = version {
            if version.is_empty() || !version.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(SecretVaultInvalidParametersError::create(
                    "secret_version",
                    format!(
                        "Azure Key Vault secret versions allow only 0-9, a-z and A-Z: {version:?}"
                    ),
                ));
            }
        }

        Ok(Self { name, version })
    }
}

impl std::fmt::Display for KeyVaultSecretId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.version {
            Some(version) => write!(f, "{}/{version}", self.name),
            None => f.write_str(self.name),
        }
    }
}

fn timestamp_from_azure(date_time: OffsetDateTime) -> SecretVaultResult<Timestamp> {
    Timestamp::from_nanosecond(date_time.unix_timestamp_nanos()).map_err(|err| {
        SecretVaultInvalidParametersError::create(
            "timestamp",
            format!("Azure Key Vault timestamp {date_time} is out of range: {err}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
    use azure_core::error::ErrorKind;
    use azure_core::http::StatusCode;
    use azure_core::time::{Duration, OffsetDateTime};

    const SECRET_PLAINTEXT: &str = "plaintext-that-must-not-leak";

    /// Key Vault `GET /secrets/{name}/{version}` response body, timestamps in Unix seconds.
    const DB_PASSWORD_RESPONSE: &str = r#"{
        "value": "plaintext-that-must-not-leak",
        "id": "https://test-vault.vault.azure.net/secrets/db-password/4387e9f3d6e14c459867679a90fd0f79",
        "attributes": {
            "enabled": true,
            "created": 1700000000,
            "updated": 1700000100,
            "exp": 1800000000
        },
        "tags": { "team": "payments" }
    }"#;

    #[derive(Debug)]
    struct UnusedCredential;

    #[async_trait]
    impl TokenCredential for UnusedCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            Ok(AccessToken::new(
                "unused-token",
                OffsetDateTime::now_utc() + Duration::hours(1),
            ))
        }
    }

    fn source(read_metadata: bool) -> AzureKeyVaultSource {
        AzureKeyVaultSource::with_options(
            AzureKeyVaultSourceOptions::new("https://test-vault.vault.azure.net".into())
                .with_read_metadata(read_metadata),
            Arc::new(UnusedCredential),
        )
        .unwrap()
    }

    fn db_password_response() -> models::Secret {
        azure_core::json::from_json(DB_PASSWORD_RESPONSE).unwrap()
    }

    #[test]
    fn names_and_versions_outside_key_vault_charset_are_rejected() {
        for invalid_name in ["db_password", "db/password", "db-password?x=1", ""] {
            let key = SecretVaultKey::new(invalid_name.into());
            assert!(
                matches!(
                    KeyVaultSecretId::try_from(&key),
                    Err(SecretVaultError::InvalidParametersError(_))
                ),
                "{invalid_name:?} must be rejected"
            );
        }

        let path_escaping_version =
            SecretVaultKey::new("db-password".into()).with_secret_version("../other".into());
        assert!(matches!(
            KeyVaultSecretId::try_from(&path_escaping_version),
            Err(SecretVaultError::InvalidParametersError(_))
        ));

        let valid = SecretVaultKey::new("db-Password-2".into())
            .with_secret_version("4387e9f3d6e14c459867679a90fd0f79".into());
        assert!(KeyVaultSecretId::try_from(&valid).is_ok());
    }

    #[test]
    fn metadata_maps_tags_expiry_timestamps_and_version() {
        let secret_ref = SecretVaultRef::new("db-password".into());
        let secret = source(true)
            .secret_from_key_vault(&secret_ref, db_password_response())
            .unwrap()
            .unwrap();

        assert_eq!(secret.value.as_sensitive_str(), SECRET_PLAINTEXT);
        let metadata = secret.metadata;
        assert_eq!(
            metadata.labels,
            Some(vec![
                SecretMetadataLabel::new("team".into()).with_value("payments".into())
            ])
        );
        assert_eq!(
            metadata.expiration,
            Some(SecretExpiration::ExpireTime(
                Timestamp::from_second(1800000000).unwrap()
            ))
        );
        assert_eq!(
            metadata.created_at,
            Some(Timestamp::from_second(1700000000).unwrap())
        );
        assert_eq!(
            metadata.updated_at,
            Some(Timestamp::from_second(1700000100).unwrap())
        );
        assert_eq!(
            metadata.version,
            Some("4387e9f3d6e14c459867679a90fd0f79".into())
        );
    }

    #[test]
    fn metadata_is_left_empty_unless_requested() {
        let secret_ref = SecretVaultRef::new("db-password".into());
        let metadata = source(false)
            .secret_from_key_vault(&secret_ref, db_password_response())
            .unwrap()
            .unwrap()
            .metadata;

        assert_eq!(metadata.labels, None);
        assert_eq!(metadata.expiration, None);
        assert_eq!(metadata.created_at, None);
        assert_eq!(
            metadata.version,
            Some("4387e9f3d6e14c459867679a90fd0f79".into())
        );
    }

    #[test]
    fn secret_value_is_absent_from_debug_and_error_output() {
        let secret_ref = SecretVaultRef::new("db-password".into());
        let secret = source(true)
            .secret_from_key_vault(&secret_ref, db_password_response())
            .unwrap()
            .unwrap();
        assert!(!format!("{secret:?}").contains(SECRET_PLAINTEXT));
        assert!(!format!("{:?}", source(true)).contains(SECRET_PLAINTEXT));

        let malformed_response =
            r#"{"value": "plaintext-that-must-not-leak", "attributes": {"created": "yesterday"}}"#;
        let decode_error = SecretVaultError::from(
            azure_core::json::from_json::<_, models::Secret>(malformed_response).unwrap_err(),
        );
        assert!(!format!("{decode_error:?}").contains(SECRET_PLAINTEXT));
        assert!(!decode_error.to_string().contains(SECRET_PLAINTEXT));
    }

    #[test]
    fn not_found_response_maps_to_data_not_found() {
        let not_found = azure_core::Error::new(
            ErrorKind::HttpResponse {
                status: StatusCode::NotFound,
                error_code: Some("SecretNotFound".into()),
                raw_response: None,
            },
            "secret not found",
        );
        assert!(matches!(
            SecretVaultError::from(not_found),
            SecretVaultError::DataNotFoundError(_)
        ));

        let forbidden = azure_core::Error::new(
            ErrorKind::HttpResponse {
                status: StatusCode::Forbidden,
                error_code: Some("Forbidden".into()),
                raw_response: None,
            },
            "forbidden",
        );
        assert!(matches!(
            SecretVaultError::from(forbidden),
            SecretVaultError::SecretsSourceError(_)
        ));
    }
}

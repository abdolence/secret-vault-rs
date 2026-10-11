//! Tests against the Lowkey Vault Key Vault emulator. They are ignored by default; to run them:
//!
//! ```sh
//! docker run --rm -d --name lowkey-vault -p 8443:8443 docker.io/nagyesta/lowkey-vault:7.3.112
//! AZURE_KEY_VAULT_EMULATOR_URL=https://localhost:8443 \
//!   cargo test -p secret-vault --features azure-keyvault --test azure_key_vault_emulator -- --ignored
//! ```

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::http::{ClientOptions, RequestContent, Transport};
use azure_core::time::{Duration, OffsetDateTime};
use azure_security_keyvault_secrets::models::{SecretAttributes, SetSecretParameters};
use azure_security_keyvault_secrets::{ResourceExt, SecretClient, SecretClientOptions};
use secret_vault::azure::{AzureKeyVaultSource, AzureKeyVaultSourceOptions};
use secret_vault::errors::SecretVaultError;
use secret_vault::*;
use std::collections::HashMap;
use std::sync::Arc;

const EMULATOR_URL_ENV: &str = "AZURE_KEY_VAULT_EMULATOR_URL";

/// Lowkey Vault accepts any bearer token, so no identity endpoint is involved.
#[derive(Debug)]
struct EmulatorCredential;

#[async_trait::async_trait]
impl TokenCredential for EmulatorCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            "emulator-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
    }
}

struct Emulator {
    vault_url: String,
    client: SecretClient,
}

impl Emulator {
    fn connect() -> Self {
        let vault_url = std::env::var(EMULATOR_URL_ENV)
            .unwrap_or_else(|_| panic!("{EMULATOR_URL_ENV} must point at a Lowkey Vault"));
        let client = SecretClient::new(
            &vault_url,
            Arc::new(EmulatorCredential),
            Some(Self::client_options()),
        )
        .unwrap();
        Self { vault_url, client }
    }

    /// The emulator serves a self-signed certificate and names itself, not a Key Vault domain,
    /// as the authentication challenge resource.
    fn client_options() -> SecretClientOptions {
        // With this feature the application installs the provider; an install that finds one
        // already installed by another test changes nothing.
        #[cfg(feature = "azure-keyvault-rustls-no-provider")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let http_client = reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let client_options = ClientOptions {
            transport: Some(Transport::new(Arc::new(http_client))),
            ..Default::default()
        };
        SecretClientOptions {
            client_options,
            verify_challenge_resource: Some(false),
            ..Default::default()
        }
    }

    fn source(&self, read_metadata: bool) -> AzureKeyVaultSource {
        AzureKeyVaultSource::with_options(
            AzureKeyVaultSourceOptions::new(self.vault_url.clone())
                .with_read_metadata(read_metadata)
                .with_client_options(Self::client_options()),
            Arc::new(EmulatorCredential),
        )
        .unwrap()
    }

    /// Stores a new version of `name` and returns that version's identifier.
    async fn set_secret(&self, name: &str, value: &str, parameters: SetSecretParameters) -> String {
        let parameters = SetSecretParameters {
            value: Some(value.into()),
            ..parameters
        };
        let stored = self
            .client
            .set_secret(name, RequestContent::try_from(parameters).unwrap(), None)
            .await
            .unwrap()
            .into_model()
            .unwrap();
        stored.resource_id().unwrap().version.unwrap()
    }
}

/// Emulator state outlives a test run, so every run writes to fresh secret names.
fn unique_name(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn reads_latest_secret_with_metadata() {
    let emulator = Emulator::connect();
    let name = unique_name("db-password");
    let attributes = SecretAttributes {
        expires: Some(OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()),
        ..Default::default()
    };
    emulator
        .set_secret(&name, "first-value", SetSecretParameters::default())
        .await;
    let latest_version = emulator
        .set_secret(
            &name,
            "latest-value",
            SetSecretParameters {
                secret_attributes: Some(attributes),
                tags: Some(HashMap::from([("team".into(), "payments".into())])),
                ..Default::default()
            },
        )
        .await;

    let secret_ref = SecretVaultRef::new(name.as_str().into());
    let secrets = emulator
        .source(true)
        .get_secrets(std::slice::from_ref(&secret_ref))
        .await
        .unwrap();

    let secret = &secrets[&secret_ref];
    assert_eq!(secret.value.as_sensitive_str(), "latest-value");
    assert_eq!(
        secret.metadata.version,
        Some(latest_version.as_str().into())
    );
    assert_eq!(
        secret.metadata.labels,
        Some(vec![
            SecretMetadataLabel::new("team".into()).with_value("payments".into())
        ])
    );
    assert_eq!(
        secret.metadata.expiration,
        Some(SecretExpiration::ExpireTime(
            jiff::Timestamp::from_second(1_900_000_000).unwrap()
        ))
    );
    assert!(secret.metadata.created_at.is_some());
    assert!(secret.metadata.updated_at.is_some());
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn reads_requested_version() {
    let emulator = Emulator::connect();
    let name = unique_name("api-key");
    let first_version = emulator
        .set_secret(&name, "first-value", SetSecretParameters::default())
        .await;
    emulator
        .set_secret(&name, "second-value", SetSecretParameters::default())
        .await;

    let secret_ref = SecretVaultRef::new(name.as_str().into())
        .with_secret_version(first_version.as_str().into());
    let secrets = emulator
        .source(false)
        .get_secrets(std::slice::from_ref(&secret_ref))
        .await
        .unwrap();

    assert_eq!(secrets[&secret_ref].value.as_sensitive_str(), "first-value");
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn missing_secret_fails_only_when_required() {
    let emulator = Emulator::connect();
    let missing = SecretVaultRef::new(unique_name("missing").as_str().into());

    let optional = emulator
        .source(false)
        .get_secrets(&[missing.clone().with_required(false)])
        .await
        .unwrap();
    assert!(optional.is_empty());

    let required = emulator
        .source(false)
        .get_secrets(&[missing.with_required(true)])
        .await;
    assert!(matches!(
        required,
        Err(SecretVaultError::DataNotFoundError(_))
    ));
}

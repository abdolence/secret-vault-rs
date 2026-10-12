//! Tests against the Lowkey Vault Key Vault emulator. They are ignored by default; to run them:
//!
//! ```sh
//! docker run --rm -d --name lowkey-vault -p 8443:8443 docker.io/nagyesta/lowkey-vault:7.3.112
//! AZURE_KEY_VAULT_EMULATOR_URL=https://localhost:8443 \
//!   cargo test -p secret-vault --features azure-keyvault,azure-kms --test azure_key_vault_emulator -- --ignored
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

    /// The emulator serves a self-signed certificate.
    fn http_client_options() -> ClientOptions {
        // With this feature the application installs the provider; an install that finds one
        // already installed by another test changes nothing.
        #[cfg(feature = "azure-keyvault-tls-no-provider")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http_client = reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        ClientOptions {
            transport: Some(Transport::new(Arc::new(http_client))),
            ..Default::default()
        }
    }

    /// The emulator names itself, not a Key Vault domain, as the authentication challenge
    /// resource.
    fn client_options() -> SecretClientOptions {
        SecretClientOptions {
            client_options: Self::http_client_options(),
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

#[cfg(feature = "azure-kms-base")]
mod kms {
    use super::*;
    use azure_security_keyvault_keys::models::{CreateKeyParameters, KeyOperation, KeyType};
    use azure_security_keyvault_keys::ResourceExt as _;
    use azure_security_keyvault_keys::{KeyClient, KeyClientOptions};
    use rvstruct::ValueStruct;
    use secret_vault::azure::{
        AzureKmsEnvelopeEncryption, AzureKmsKeyRef, AzureKmsProviderOptions, KmsKeyVersion,
    };
    use secret_vault_value::SecretValue;

    fn key_client_options() -> KeyClientOptions {
        KeyClientOptions {
            client_options: Emulator::http_client_options(),
            verify_challenge_resource: Some(false),
            ..Default::default()
        }
    }

    /// Creates an RSA key and returns its version: Lowkey Vault wraps only with an explicit
    /// key version.
    async fn create_rsa_key(vault_url: &str, key_name: &str) -> KmsKeyVersion {
        let client = KeyClient::new(
            vault_url,
            Arc::new(EmulatorCredential),
            Some(key_client_options()),
        )
        .unwrap();
        let parameters = CreateKeyParameters {
            kty: Some(KeyType::Rsa),
            key_size: Some(2048),
            // Lowkey Vault checks the encrypt and decrypt operations on wrap and unwrap.
            key_ops: Some(vec![
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
                KeyOperation::Encrypt,
                KeyOperation::Decrypt,
            ]),
            ..Default::default()
        };
        let key = client
            .create_key(
                key_name,
                RequestContent::try_from(parameters).unwrap(),
                None,
            )
            .await
            .unwrap()
            .into_model()
            .unwrap();
        KmsKeyVersion::try_from(key.resource_id().unwrap().version.unwrap()).unwrap()
    }

    #[tokio::test]
    #[ignore = "needs the Lowkey Vault emulator, see the module docs"]
    async fn value_round_trips_through_azure_kms_envelope_encryption() {
        let emulator = Emulator::connect();
        let key_name = unique_name("secret-vault-dek");
        let key_version = create_rsa_key(&emulator.vault_url, &key_name).await;
        let encryption = AzureKmsEnvelopeEncryption::with_options(
            &AzureKmsKeyRef::new(emulator.vault_url.clone(), key_name)
                .with_key_version(key_version),
            AzureKmsProviderOptions::new().with_client_options(key_client_options()),
            Arc::new(EmulatorCredential),
        )
        .await
        .unwrap();
        let secret_vault_key = SecretVaultKey::new(SecretName::from_static("db-password"));
        let secret_value = SecretValue::from("test-secret");

        let encrypted_value = encryption
            .encrypt_value(&secret_vault_key, &secret_value)
            .await
            .unwrap();
        assert_ne!(encrypted_value.value(), secret_value.ref_sensitive_value());

        let decrypted_value = encryption
            .decrypt_value(&secret_vault_key, &encrypted_value)
            .await
            .unwrap();
        assert_eq!(decrypted_value.as_sensitive_str(), "test-secret");
    }
}

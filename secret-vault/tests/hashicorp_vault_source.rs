//! Integration tests against a live Vault server with a KV v2 engine at `secret/`.
//!
//! Ignored by default. Run them against a dev server:
//!
//! ```sh
//! docker run -d --rm --name vault-dev -p 8200:8200 \
//!     -e VAULT_DEV_ROOT_TOKEN_ID=dev-root docker.io/hashicorp/vault:latest
//! VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//!     cargo test -p secret-vault --features hashicorp-vault --test hashicorp_vault_source -- --ignored
//! ```
#![cfg(feature = "hashicorp-vault")]

use std::collections::HashMap;

use secret_vault::errors::SecretVaultError;
use secret_vault::hashicorp::vaultrs::api::kv2::requests::SetSecretMetadataRequestBuilder;
use secret_vault::hashicorp::vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use secret_vault::hashicorp::vaultrs::kv2;
use secret_vault::hashicorp::{HashiCorpVaultSource, HashiCorpVaultSourceOptions};
use secret_vault::*;

const KV_MOUNT: &str = "secret";

/// Builds a client from `VAULT_ADDR` and `VAULT_TOKEN`, the same way the source does.
fn vault_client() -> VaultClient {
    VaultClient::new(
        VaultClientSettingsBuilder::default()
            .build()
            .expect("VAULT_ADDR and VAULT_TOKEN must be set to run the ignored Vault tests"),
    )
    .unwrap()
}

/// A path unique to one test, so tests sharing the dev server never see each other's data.
fn unique_path(test_name: &str) -> String {
    format!(
        "secret-vault-tests/{test_name}/{}",
        jiff::Timestamp::now().as_nanosecond()
    )
}

async fn write_version(path: &str, password: &str) {
    kv2::set(
        &vault_client(),
        KV_MOUNT,
        path,
        &HashMap::from([("password", password)]),
    )
    .await
    .unwrap();
}

fn read_password(secret: &Secret) -> String {
    let data: HashMap<String, String> = serde_json::from_slice(secret.value.ref_sensitive_value())
        .expect("secret value is the KV v2 data object as JSON");
    data["password"].clone()
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn reads_latest_version() {
    let path = unique_path("latest");
    write_version(&path, "first-password").await;
    write_version(&path, "second-password").await;

    let source = HashiCorpVaultSource::new().unwrap();
    let secret_ref = SecretVaultRef::new(path.into());
    let secrets = source
        .get_secrets(std::slice::from_ref(&secret_ref))
        .await
        .unwrap();

    let secret = &secrets[&secret_ref];
    assert_eq!(read_password(secret), "second-password");
    assert_eq!(secret.metadata.version, Some("2".into()));
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn reads_requested_version() {
    let path = unique_path("version");
    write_version(&path, "first-password").await;
    write_version(&path, "second-password").await;

    let source = HashiCorpVaultSource::new().unwrap();
    let secret_ref = SecretVaultRef::new(path.into()).with_secret_version("1".into());
    let secrets = source
        .get_secrets(std::slice::from_ref(&secret_ref))
        .await
        .unwrap();

    let secret = &secrets[&secret_ref];
    assert_eq!(read_password(secret), "first-password");
    assert_eq!(secret.metadata.version, Some("1".into()));
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn missing_secret_is_skipped_unless_required() {
    let path = unique_path("missing");
    let source = HashiCorpVaultSource::new().unwrap();

    let optional_ref = SecretVaultRef::new(path.clone().into()).with_required(false);
    let secrets = source
        .get_secrets(std::slice::from_ref(&optional_ref))
        .await
        .unwrap();
    assert!(secrets.is_empty());

    let required_ref = SecretVaultRef::new(path.into());
    let result = source.get_secrets(&[required_ref]).await;
    assert!(matches!(
        result,
        Err(SecretVaultError::DataNotFoundError(_))
    ));
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn custom_metadata_becomes_labels() {
    let path = unique_path("metadata");
    write_version(&path, "first-password").await;
    kv2::set_metadata(
        &vault_client(),
        KV_MOUNT,
        &path,
        Some(
            &mut SetSecretMetadataRequestBuilder::default().custom_metadata(HashMap::from([(
                "team".to_string(),
                "payments".to_string(),
            )])),
        ),
    )
    .await
    .unwrap();

    let source = HashiCorpVaultSource::with_client(
        vault_client(),
        HashiCorpVaultSourceOptions::new().with_read_metadata(true),
    );
    let secret_ref = SecretVaultRef::new(path.into());
    let secrets = source
        .get_secrets(std::slice::from_ref(&secret_ref))
        .await
        .unwrap();

    let metadata = &secrets[&secret_ref].metadata;
    assert_eq!(
        metadata.labels,
        Some(vec![
            SecretMetadataLabel::new("team".into()).with_value("payments".into())
        ])
    );
    assert!(metadata.created_at.is_some());
}

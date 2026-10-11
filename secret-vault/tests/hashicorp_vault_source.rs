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
#![cfg(feature = "hashicorp-vault-base")]

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use secret_vault::errors::SecretVaultError;
use secret_vault::hashicorp::{HashiCorpVaultSource, HashiCorpVaultSourceOptions};
use secret_vault::*;
use serde_json::json;

/// Sends a write to the Vault HTTP API of the server in `VAULT_ADDR`, over plain HTTP.
async fn vault_write(api_path: &str, body: serde_json::Value) {
    let address =
        std::env::var("VAULT_ADDR").expect("VAULT_ADDR must be set to run the ignored Vault tests");
    let token = std::env::var("VAULT_TOKEN")
        .expect("VAULT_TOKEN must be set to run the ignored Vault tests");
    let request = Request::post(format!("{address}/v1/{api_path}"))
        .header("X-Vault-Token", token)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let response = Client::builder(TokioExecutor::new())
        .build_http()
        .request(request)
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "Vault refused the write to {api_path}: {}",
        response.status()
    );
}

async fn write_version(path: &str, password: &str) {
    vault_write(
        &format!("secret/data/{path}"),
        json!({ "data": { "password": password } }),
    )
    .await;
}

/// A path unique to one test, so tests sharing the dev server never see each other's data.
fn unique_path(test_name: &str) -> String {
    format!(
        "secret-vault-tests/{test_name}/{}",
        jiff::Timestamp::now().as_nanosecond()
    )
}

fn secret_data(secret: &Secret) -> serde_json::Value {
    serde_json::from_slice(secret.value.ref_sensitive_value())
        .expect("the secret value is the KV v2 data object as JSON")
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

    let secret = secrets.get(&secret_ref).expect("the secret was written");
    assert_eq!(
        secret_data(secret),
        json!({ "password": "second-password" })
    );
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

    let secret = secrets.get(&secret_ref).expect("the version was written");
    assert_eq!(secret_data(secret), json!({ "password": "first-password" }));
    assert_eq!(secret.metadata.version, Some("1".into()));
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn missing_or_deleted_secret_is_skipped_unless_required() {
    let missing_path = unique_path("missing");
    let deleted_path = unique_path("deleted");
    write_version(&deleted_path, "first-password").await;
    vault_write(
        &format!("secret/delete/{deleted_path}"),
        json!({ "versions": [1] }),
    )
    .await;
    let source = HashiCorpVaultSource::new().unwrap();

    for path in [missing_path, deleted_path] {
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
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn unknown_mount_fails_even_for_optional_refs() {
    let path = unique_path("unknown-mount");
    write_version(&path, "first-password").await;

    let source = HashiCorpVaultSource::with_options(
        HashiCorpVaultSourceOptions::from_env()
            .unwrap()
            .with_mount("no-such-mount".into()),
    )
    .unwrap();
    let optional_ref = SecretVaultRef::new(path.into()).with_required(false);
    let result = source.get_secrets(&[optional_ref]).await;

    assert!(matches!(
        result,
        Err(SecretVaultError::SecretsSourceError(_))
    ));
}

#[tokio::test]
#[ignore = "needs a Vault server; see the module docs"]
async fn custom_metadata_becomes_labels() {
    let path = unique_path("metadata");
    write_version(&path, "first-password").await;
    vault_write(
        &format!("secret/metadata/{path}"),
        json!({ "custom_metadata": { "team": "payments", "owner": "billing" } }),
    )
    .await;

    let source = HashiCorpVaultSource::with_options(
        HashiCorpVaultSourceOptions::from_env()
            .unwrap()
            .with_read_metadata(true),
    )
    .unwrap();
    let secret_ref = SecretVaultRef::new(path.into());
    let secrets = source
        .get_secrets(std::slice::from_ref(&secret_ref))
        .await
        .unwrap();

    let metadata = &secrets
        .get(&secret_ref)
        .expect("the secret was written")
        .metadata;
    assert_eq!(
        metadata.labels,
        Some(vec![
            SecretMetadataLabel::new("owner".into()).with_value("billing".into()),
            SecretMetadataLabel::new("team".into()).with_value("payments".into()),
        ])
    );
    assert!(metadata.created_at.is_some());
}

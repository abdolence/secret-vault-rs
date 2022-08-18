use secret_vault::*;
use std::io::Write;
use tempfile::tempdir;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Mocking a secret file
    let mock_secret_dir = tempdir()?;
    let mock_secret_file_path = mock_secret_dir.path().join("my-mock-secret.key");
    let mut mock_secret_file = std::fs::File::create(mock_secret_file_path)?;
    write!(mock_secret_file, "42424242")?;

    // Building the vault with files source
    let mut vault = SecretVaultBuilder::with_source(FilesSource::with_options(
        FilesSourceOptions::new().with_root_path(mock_secret_dir.path().into()),
    ))
    .without_encryption()
    .build()?;

    let secret_ref = SecretVaultRef::new("my-mock-secret.key".into());

    // Registering your secrets and receiving them from source
    vault
        .register_secrets_refs(vec![&secret_ref])
        .refresh()
        .await?;

    // Reading the secret value
    let secret_value: Secret = vault.require_secret_by_ref(&secret_ref).await?;

    println!(
        "Received secret: {:?}",
        secret_value.value.sensitive_value_to_str().unwrap()
    );

    Ok(())
}

use secret_vault::*;

// Secret coming from an environment variable
static SECRET_REF: SecretVaultRef = SecretVaultRef::new(SecretName::from_static("user"))
    .with_required(false)
    .with_allow_in_snapshots(true);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault with test env source
    let vault = SecretVaultBuilder::with_source(InsecureEnvSource::new())
        .without_encryption()
        .with_secret_refs(vec![&SECRET_REF])
        .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Creating a snapshot
    let snapshot = vault
        .snapshot(SecretVaultHashMapSnapshotBuilder::new())
        .await?;

    // Reading the secret value
    let secret_value: Secret = snapshot.require_secret_by_ref(&SECRET_REF)?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

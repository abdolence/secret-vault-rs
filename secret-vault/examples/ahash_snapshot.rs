use secret_vault::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Secret coming from an environment variable
    let secret_ref = SecretVaultRef::new("user".into())
        .with_required(false)
        .with_allow_in_snapshots(true);

    // Building the vault with test env source
    let vault = SecretVaultBuilder::with_source(InsecureEnvSource::new())
        .without_encryption()
        .with_secret_refs(vec![&secret_ref])
        .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Creating a snapshot
    let snapshot = vault
        .snapshot(SecretVaultAhashSnapshotBuilder::new())
        .await?;

    // Reading the secret value
    let secret_value: Secret = snapshot.require_secret_by_ref(&secret_ref)?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

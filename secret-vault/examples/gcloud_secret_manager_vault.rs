use secret_vault::*;

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Describing secrets and marking them non-required
    // since this is only example and they don't exist in your project
    let secret1 = SecretVaultRef::new("test-secret1".into()).with_required(false);
    let secret2 = SecretVaultRef::new("test-secret2".into())
        .with_secret_version("1".into())
        .with_required(false);

    // Building the vault
    let mut vault = SecretVaultBuilder::with_source(
        gcp::GoogleSecretManagerSource::new(&config_env_var("PROJECT_ID")?).await?,
    )
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .build()?;

    // Registering your secrets and receiving them from source
    vault
        .with_secrets_refs(vec![&secret1, &secret2])
        .refresh()
        .await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret1).await?;

    println!("Received secret: {:?}", secret_value);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    vault_viewer.get_secret_by_ref(&secret2).await?;

    // Using the Snapshot API to be able to share the instance without having to store `vault`
    // Since this point `vault` is not available anymore to borrow and update secrets
    let vault_snapshot = vault.snapshot();
    vault_snapshot.get_secret_by_ref(&secret2).await?;

    Ok(())
}

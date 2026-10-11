use secret_vault::*;

// Describing secrets and marking them non-required
// since this is only example and they don't exist in your project
static SECRET_REF: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("user")).with_required(false);

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{name}: {e}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault
    let vault = SecretVaultBuilder::with_source(InsecureEnvSource::new())
        .without_encryption()
        .with_secret_refs(vec![&SECRET_REF])
        .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&SECRET_REF).await?;

    println!("Received secret: {secret_value:?}");

    Ok(())
}

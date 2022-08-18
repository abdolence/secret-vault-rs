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
    let secret_ref = SecretVaultRef::new("user".into()).with_required(false);

    // Building the vault
    let vault = SecretVaultBuilder::with_source(InsecureEnvSource::new())
        .without_encryption()
        .with_secret_refs(vec![&secret_ref])
        .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret_ref).await?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

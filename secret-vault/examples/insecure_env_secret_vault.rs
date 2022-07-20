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
    let secret = SecretVaultRef::new("user".into()).with_required(false);

    // Building the vault
    let mut vault = SecretVaultBuilder::with_source(InsecureEnvSource::new())
        .without_encryption()
        .build()?;

    // Registering your secrets and receiving them from source
    vault.with_secrets_refs(vec![&secret]).refresh().await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret)?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

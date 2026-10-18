use secret_vault::*;

// Describing secrets and marking them non-required
// since this is only example and they don't exist in your Vault
static SECRET_REF: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("my-app/database")).with_required(false);

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault. The source and the encryption both read VAULT_ADDR, VAULT_TOKEN,
    // VAULT_NAMESPACE and VAULT_CACERT.
    let vault = SecretVaultBuilder::with_source(hashicorp::HashiCorpVaultSource::new()?)
        .with_encryption(hashicorp::HcVaultTransitEnvelopeEncryption::<AwsLc>::new(
            &hashicorp::HcVaultTransitKeyRef::new(config_env_var("VAULT_TRANSIT_KEY")?),
        )?)
        .with_secret_refs(vec![&SECRET_REF])
        .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&SECRET_REF).await?;

    println!("Received secret: {:?}", secret_value);
    Ok(())
}

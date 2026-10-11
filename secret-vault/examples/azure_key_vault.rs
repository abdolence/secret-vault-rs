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
    let secret_ref1 = SecretVaultRef::new("test-secret1".into()).with_required(false);
    let secret_ref2 = SecretVaultRef::new("test-secret2".into())
        .with_secret_version("4387e9f3d6e14c459867679a90fd0f79".into())
        .with_required(false);

    // Azure CLI or Azure Developer CLI credentials for local runs;
    // use `azure_identity::ManagedIdentityCredential` in Azure deployments
    let credential = azure_identity::DeveloperToolsCredential::new(None)?;

    // Building the vault
    let vault = SecretVaultBuilder::with_source(azure::AzureKeyVaultSource::with_options(
        azure::AzureKeyVaultSourceOptions::new(config_env_var("VAULT_URL")?)
            .with_read_metadata(true),
        credential,
    )?)
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_secret_refs(vec![&secret_ref1, &secret_ref2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret_ref1).await?;
    // Or if you require it available
    // let secret_value: Secret = vault.require_secret_by_ref(&secret_ref1).await?;

    println!("Received secret: {:?}", secret_value);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    vault_viewer.get_secret_by_ref(&secret_ref2).await?;

    Ok(())
}

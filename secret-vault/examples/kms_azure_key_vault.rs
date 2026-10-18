use secret_vault::*;

// Describing secrets and marking them non-required
// since this is only example and they don't exist in your project
static SECRET_REF: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("test-secret1")).with_required(false);

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let vault_url = config_env_var("VAULT_URL")?;
    let kms_key_name = config_env_var("KMS_KEY_NAME")?;

    // Azure CLI or Azure Developer CLI credentials for local runs;
    // use `azure_identity::ManagedIdentityCredential` in Azure deployments
    let credential = azure_identity::DeveloperToolsCredential::new(None)?;

    // Building the vault
    let vault = SecretVaultBuilder::with_source(azure::AzureKeyVaultSource::new(
        &vault_url,
        credential.clone(),
    )?)
    .with_encryption(azure::AzureKmsEnvelopeEncryption::<AwsLc>::new(
        &azure::AzureKmsKeyRef::new(vault_url, kms_key_name),
        credential,
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

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
    let google_project_id = config_env_var("PROJECT_ID")?;
    let google_project_location = config_env_var("PROJECT_LOCATION")?;
    let google_kms_key_ring = config_env_var("KMS_KEY_RING")?;
    let google_kms_key = config_env_var("KMS_KEY")?;

    // Describing secrets and marking them non-required
    // since this is only example and they don't exist in your project
    let secret1 = SecretVaultRef::new("test-secret1".into()).with_required(false);

    // Building the vault
    let mut vault = SecretVaultBuilder::with_source(
        gcp::GoogleSecretManagerSource::new(&google_project_id).await?,
    )
    .with_encryption(
        gcp::GoogleKmsEnvelopeEncryption::new(&gcp::GoogleKmsKeyRef::new(
            google_project_id,
            google_project_location,
            google_kms_key_ring,
            google_kms_key,
        ))
        .await?,
    )
    .build()?;

    // Registering your secrets and receiving them from source
    vault
        .register_secrets_refs(vec![&secret1])
        .refresh()
        .await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret1).await?;

    println!("Received secret: {:?}", secret_value);
    Ok(())
}

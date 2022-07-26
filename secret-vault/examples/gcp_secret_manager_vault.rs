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
    let secret1_ref = SecretVaultRef::new("tm-http-sessions-secret".into()).with_required(false);
    let secret_ref2 = SecretVaultRef::new("test-secret2".into())
        .with_secret_version("1".into())
        .with_required(false);

    // Building the vault
    let vault = SecretVaultBuilder::with_source(
        gcp::GcpSecretManagerSource::with_options(
            gcp::GcpSecretManagerSourceOptions::new(config_env_var("PROJECT_ID")?)
                .with_read_metadata(true),
        )
        .await?,
    )
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_secret_refs(vec![&secret1_ref, &secret_ref2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret values
    let secret: Option<Secret> = vault.get_secret_by_ref(&secret1_ref).await?;

    // Or if you require it available
    // let secret_value: Secret = vault.require_secret_by_ref(&secret1).await?;

    println!("Received secret: {:?}", secret);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    let secret2 = vault_viewer.get_secret_by_ref(&secret_ref2).await?;

    println!("Received secret: {:?}", secret2);

    Ok(())
}

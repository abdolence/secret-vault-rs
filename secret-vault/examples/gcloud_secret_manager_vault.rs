use secret_vault::locked_allocator::SecretVaultStoreMemoryProtectAllocator;
use secret_vault::*;
use secret_vault_value::SecretValue;

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
    let secret2 = SecretVaultRef::new("test-secret1".into()).with_secret_version("1".into()).with_required(false);

    // Building the vault
    let mut vault = SecretVaultBuilder::with_source(
        gcp::GoogleSecretManagerSource::new(&config_env_var("PROJECT_ID")?).await?,
    )
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_memory_protection(SecretVaultStoreMemoryProtectAllocator::new())
    .build()?;

    // Registering your secrets and receiving them from source
    vault.with_secrets_refs(vec![
        &secret1,
        &secret2
    ])
    .refresh().await?;

    // Reading the secret values
    let secret_value: Option<SecretValue> = vault.get_secret_by_ref(&secret1)?;

    println!("Received secret: {:?}", secret_value);

    // Using the viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    vault_viewer.get_secret_by_ref(&secret2)?;

    Ok(())
}

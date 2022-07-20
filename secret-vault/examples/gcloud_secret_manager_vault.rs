use secret_vault::locked_allocator::SecretVaultStoreMemoryProtectAllocator;
use secret_vault::*;

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("slack_morphism_hyper=debug,slack_morphism=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let vault = SecretVaultBuilder::with_source(
        gcp::GoogleSecretManagerSource::new(&config_env_var("PROJECT_ID")?).await?,
    )
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_memory_protection(SecretVaultStoreMemoryProtectAllocator::new())
    .build()?;

    println!("Test");

    Ok(())
}

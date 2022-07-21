use secret_vault::*;
use std::sync::Arc;
use std::time::Duration;

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=trace")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Describing secrets and marking them non-required
    let secret1 = SecretVaultRef::new("test-secret-xRnpry".into())
        .with_required(false)
        .with_secret_version("AWSCURRENT".into())
        .with_auto_refresh(true);

    // Building the vault
    let vault = Arc::new(
        SecretVaultBuilder::with_source(
            aws::AmazonSecretManagerSource::new(&config_env_var("ACCOUNT_ID")?, None).await?,
        )
        .build()?
        .with_secrets_refs(vec![secret1]),
    );

    // Refresh the secrets first to make sure they loaded first time
    vault.refresh().await?;

    let mut vault_refresher = SecretVaultAutoRefresher::new(
        vault,
        SecretVaultAutoRefresherOptions::new(
            Duration::from_secs(5), // refresh every 5 seconds, please use appropriate (and usually bigger) interval, this is only for example not to wait long
        ),
    );

    vault_refresher.start().await?;

    // You supposed to wait signals, etc, but for the sake of example here it is just sleep
    tokio::time::sleep(Duration::from_secs(10)).await;

    vault_refresher.shutdown().await?;

    Ok(())
}

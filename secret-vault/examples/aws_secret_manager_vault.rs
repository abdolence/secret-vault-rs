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
    let secret_ref1 = SecretVaultRef::new("test-secret-xRnpry".into())
        .with_required(false)
        .with_secret_version("AWSCURRENT".into());
    let secret_ref2 = SecretVaultRef::new("another-secret-222222".into()).with_required(false);

    // Building the vault
    let vault = SecretVaultBuilder::with_source(
        aws::AwsSecretManagerSource::with_options(
            aws::AwsSecretManagerSourceOptions::new(config_env_var("ACCOUNT_ID")?)
                .with_read_metadata(true),
        )
        .await?,
    )
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_secret_refs(vec![&secret_ref1, &secret_ref2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret_ref1).await?;
    // Or if you require it available
    // let secret_value: Secret = vault.require_secret_by_ref(&secret1).await?;
    // To work with embedded JSON from Amazon you can use `expose_json_value_as` from `secret_value.value`

    println!("Received secret: {:?}", secret_value);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    vault_viewer.get_secret_by_ref(&secret_ref2).await?;

    Ok(())
}

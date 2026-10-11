use secret_vault::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Describing secrets and marking them non-required
    // since this is only example and they don't exist in your Vault
    let secret_ref1 = SecretVaultRef::new("my-app/database".into()).with_required(false);
    let secret_ref2 = SecretVaultRef::new("my-app/api-keys".into())
        .with_secret_version("1".into())
        .with_required(false);

    // Building the vault. The options read VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE and VAULT_CACERT.
    let vault = SecretVaultBuilder::with_source(hashicorp::HashiCorpVaultSource::with_options(
        hashicorp::HashiCorpVaultSourceOptions::from_env()?
            .with_mount("secret".into())
            .with_read_metadata(true),
    )?)
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_secret_refs(vec![&secret_ref1, &secret_ref2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret values
    let secret: Option<Secret> = vault.get_secret_by_ref(&secret_ref1).await?;

    // Or if you require it available
    // let secret_value: Secret = vault.require_secret_by_ref(&secret_ref1).await?;

    println!("Received secret: {:?}", secret);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    let secret2 = vault_viewer.get_secret_by_ref(&secret_ref2).await?;

    println!("Received secret: {:?}", secret2);

    Ok(())
}

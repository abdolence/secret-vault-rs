use secret_vault::*;

// Describing secrets and marking them non-required
// since this is only example and they don't exist in your Vault
static SECRET_REF1: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("my-app/database")).with_required(false);
static SECRET_REF2: SecretVaultRef = SecretVaultRef::from_key(SecretVaultKey::from_parts(
    SecretName::from_static("my-app/api-keys"),
    Some(SecretVersion::from_static("1")),
    None,
))
.with_required(false);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault. The options read VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, VAULT_CACERT
    // and VAULT_CLIENT_TIMEOUT.
    let vault = SecretVaultBuilder::with_source(hashicorp::HashiCorpVaultSource::with_options(
        hashicorp::HashiCorpVaultSourceOptions::from_env()?
            .with_mount("secret".into())
            .with_read_metadata(true),
    )?)
    .with_encryption(aead_encryption::SecretVaultAeadEncryption::<AwsLc>::new()?)
    .with_secret_refs(vec![&SECRET_REF1, &SECRET_REF2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret values
    let secret: Option<Secret> = vault.get_secret_by_ref(&SECRET_REF1).await?;

    // Or if you require it available
    // let secret_value: Secret = vault.require_secret_by_ref(&SECRET_REF1).await?;

    println!("Received secret: {:?}", secret);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    let secret2 = vault_viewer.get_secret_by_ref(&SECRET_REF2).await?;

    println!("Received secret: {:?}", secret2);

    Ok(())
}

use secret_vault::*;

// Describing secrets and marking them non-required
// since this is only example and they don't exist in your project
static SECRET_REF1: SecretVaultRef = SecretVaultRef::from_key(SecretVaultKey::from_parts(
    SecretName::from_static("test-secret-xRnpry"),
    Some(SecretVersion::from_static("AWSCURRENT")),
    None,
))
.with_required(false);
static SECRET_REF2: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("another-secret-222222")).with_required(false);

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault
    let vault = SecretVaultBuilder::with_source(
        aws::AwsSecretManagerSource::with_options(
            aws::AwsSecretManagerSourceOptions::new(config_env_var("ACCOUNT_ID")?)
                .with_read_metadata(true),
        )
        .await?,
    )
    .with_encryption(aead_encryption::SecretVaultAeadEncryption::new(
        AeadBackend::AwsLc,
    )?)
    .with_secret_refs(vec![&SECRET_REF1, &SECRET_REF2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&SECRET_REF1).await?;
    // Or if you require it available
    // let secret_value: Secret = vault.require_secret_by_ref(&SECRET_REF1).await?;
    // To work with embedded JSON from Amazon you can use `expose_json_value_as` from `secret_value.value`

    println!("Received secret: {:?}", secret_value);

    // Using the Viewer API to share only methods able to read secrets
    let vault_viewer = vault.viewer();
    vault_viewer.get_secret_by_ref(&SECRET_REF2).await?;

    Ok(())
}

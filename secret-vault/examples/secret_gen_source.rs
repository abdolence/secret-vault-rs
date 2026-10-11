use secret_vault::*;
use std::ops::Deref;

static SECRET_REF1: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("my-temp-secret-pregen"));
static SECRET_REF2: SecretVaultRef =
    SecretVaultRef::new(SecretName::from_static("my-temp-secret-autogen-on-refresh"));

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault with files source
    let vault = SecretVaultBuilder::with_source(TempSecretGenSource::with_options(
        TempSecretGenSourceOptions::new()
            .add_secret_generator(
                &SECRET_REF1.key,
                TempSecretOptions::new(32)
                    .with_regenerate_on_refresh(false)
                    .with_printable(true),
            )
            .add_secret_generator(
                &SECRET_REF2.key,
                TempSecretOptions::new(64)
                    .with_regenerate_on_refresh(true)
                    .with_printable(false),
            ),
    )?)
    .with_secret_refs(vec![&SECRET_REF1, &SECRET_REF2])
    .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret value
    let secret_value1: Secret = vault.require_secret_by_ref(&SECRET_REF1).await?;
    let secret_value2: Secret = vault.require_secret_by_ref(&SECRET_REF2).await?;

    println!(
        "Received secret:\n{}\n{}",
        secret_value1.value.sensitive_value_to_str().unwrap(),
        secret_value2.value.as_sensitive_hex_str().deref()
    );

    Ok(())
}

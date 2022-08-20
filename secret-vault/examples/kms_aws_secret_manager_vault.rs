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

    let aws_account_id = config_env_var("ACCOUNT_ID")?;
    let aws_key_id: String = config_env_var("KMS_KEY_ID")?;

    // Describing secrets and marking them non-required
    // since this is only example and they don't exist in your project
    let secret_ref = SecretVaultRef::new("test-secret-xRnpry".into()).with_required(false);

    // Building the vault
    let vault =
        SecretVaultBuilder::with_source(aws::AwsSecretManagerSource::new(&aws_account_id).await?)
            .with_encryption(
                aws::AwsKmsEnvelopeEncryption::new(&aws::AwsKmsKeyRef::new(
                    aws_account_id,
                    aws_key_id,
                ))
                .await?,
            )
            .with_secret_refs(vec![&secret_ref])
            .build()?;

    // Load secrets from the source
    vault.refresh().await?;

    // Reading the secret
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret_ref).await?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

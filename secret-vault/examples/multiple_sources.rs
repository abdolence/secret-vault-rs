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

    let secret_aws_namespace: SecretNamespace = "aws".into();
    let secret_env_namespace: SecretNamespace = "env".into();

    let secret_ref_aws = SecretVaultRef::new("test-secret-xRnpry".into())
        .with_namespace(secret_aws_namespace.clone())
        .with_required(false)
        .with_secret_version("AWSCURRENT".into());

    let secret_ref_env = SecretVaultRef::new("user".into())
        .with_namespace(secret_env_namespace.clone())
        .with_required(false);

    // Building the vault with two sources: Environment and AWS
    let vault = SecretVaultBuilder::with_source(
        MultipleSecretsSources::new()
            .add_source(&secret_env_namespace, InsecureEnvSource::new())
            .add_source(
                &secret_aws_namespace,
                aws::AwsSecretManagerSource::new(&config_env_var("ACCOUNT_ID")?, None).await?,
            ),
    )
    .without_encryption()
    .with_secret_refs(vec![&secret_ref_aws, &secret_ref_env])
    .build()?;

    // Load secrets from all sources
    vault.refresh().await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret_ref_aws).await?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

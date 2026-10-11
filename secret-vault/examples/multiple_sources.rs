use secret_vault::*;

const AWS_NAMESPACE: SecretNamespace = SecretNamespace::from_static("aws");
const ENV_NAMESPACE: SecretNamespace = SecretNamespace::from_static("env");

static SECRET_REF_AWS: SecretVaultRef = SecretVaultRef::from_key(SecretVaultKey::from_parts(
    SecretName::from_static("test-secret-xRnpry"),
    Some(SecretVersion::from_static("AWSCURRENT")),
    Some(AWS_NAMESPACE),
))
.with_required(false);

static SECRET_REF_ENV: SecretVaultRef = SecretVaultRef::from_key(SecretVaultKey::from_parts(
    SecretName::from_static("user"),
    None,
    Some(ENV_NAMESPACE),
))
.with_required(false);

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("secret_vault=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Building the vault with two sources: Environment and AWS
    let vault = SecretVaultBuilder::with_source(
        MultipleSecretsSources::new()
            .add_source(&ENV_NAMESPACE, InsecureEnvSource::new())
            .add_source(
                &AWS_NAMESPACE,
                aws::AwsSecretManagerSource::new(&config_env_var("ACCOUNT_ID")?).await?,
            ),
    )
    .without_encryption()
    .with_secret_refs(vec![&SECRET_REF_AWS, &SECRET_REF_ENV])
    .build()?;

    // Load secrets from all sources
    vault.refresh().await?;

    // Reading the secret values
    let secret_value: Option<Secret> = vault.get_secret_by_ref(&SECRET_REF_AWS).await?;

    println!("Received secret: {:?}", secret_value);

    Ok(())
}

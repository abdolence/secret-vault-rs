use gcp_secrets::*;

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create an instance
    let secret_manager = FirestoreDb::new(&config_env_var("PROJECT_ID")?).await?;

    Ok(())
}

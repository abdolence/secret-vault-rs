//! Sources whose TLS stack takes the process default rustls `CryptoProvider` must report a
//! missing one as an error rather than panic. These tests run in their own process, so nothing
//! installs a provider before them.

#[cfg(all(
    feature = "gcp-secretmanager-base",
    feature = "hashicorp-vault-tls-ring"
))]
#[tokio::test]
async fn gcp_secret_manager_source_requires_installed_crypto_provider() {
    let result = secret_vault::gcp::GcpSecretManagerSource::new("test-project").await;

    assert!(matches!(
        result,
        Err(secret_vault::errors::SecretVaultError::InvalidParametersError(_))
    ));
}

#[cfg(feature = "azure-keyvault-tls-no-provider")]
#[test]
fn azure_key_vault_source_requires_installed_crypto_provider() {
    use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
    use azure_core::time::{Duration, OffsetDateTime};

    #[derive(Debug)]
    struct UnusedCredential;

    #[async_trait::async_trait]
    impl TokenCredential for UnusedCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            Ok(AccessToken::new(
                "unused-token",
                OffsetDateTime::now_utc() + Duration::hours(1),
            ))
        }
    }

    let result = secret_vault::azure::AzureKeyVaultSource::new(
        "https://test-vault.vault.azure.net",
        std::sync::Arc::new(UnusedCredential),
    );

    assert!(matches!(
        result,
        Err(secret_vault::errors::SecretVaultError::InvalidParametersError(_))
    ));
}

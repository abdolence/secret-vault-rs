use crate::errors::*;
use crate::SecretVaultResult;

/// Fails unless the application has installed a process default rustls `CryptoProvider`.
///
/// For sources whose TLS stack builds its rustls config from the process default and panics
/// without one: tonic in a build that compiles both the ring and aws-lc-rs providers, and
/// reqwest with only `rustls-no-provider`.
pub(crate) fn require_installed_crypto_provider() -> SecretVaultResult<()> {
    match rustls::crypto::CryptoProvider::get_default() {
        Some(_) => Ok(()),
        None => Err(SecretVaultInvalidParametersError::create(
            "crypto_provider",
            "No rustls CryptoProvider is installed: install one with `CryptoProvider::install_default` before creating the source".into(),
        )),
    }
}

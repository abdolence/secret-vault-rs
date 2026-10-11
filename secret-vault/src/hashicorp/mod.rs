mod hashicorp_vault_source;
pub use hashicorp_vault_source::*;

/// The Vault client crate, re-exported so a caller building its own client
/// uses the same version this crate was compiled against.
pub use vaultrs;

#![allow(unused_parens)]

mod allocator;
pub use allocator::*;

mod encryption;
pub mod errors;
mod secrets_source;
pub use secrets_source::*;

mod vault_store;

mod common_types;

#[cfg(feature = "locked")]
pub mod locked_allocator;

#[cfg(feature = "encrypted-ring")]
pub mod ring_encryption;

#[cfg(feature = "gcloud")]
pub mod gcp;

pub type SecretVaultResult<T> = std::result::Result<T, errors::SecretVaultError>;

mod vault;
pub use vault::*;
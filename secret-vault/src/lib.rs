//! # Secret Vault for Rust
//!
//! Library provides a secure memory-backed storage of secrets coming to your application
//! from external sources:
//!
//! - Google Cloud Secret Manager
//! - Amazon Secrets Manager
//!
//! ## Features
//! - Caching registered secrets in memory from sources;
//! - Extensible and strongly typed API to be able to implement any kind of sources;
//! - Memory encryption using AEAD cryptography (optional);
//! - Memory encryption using Google/AWS KMS envelope encryption (https://cloud.google.com/kms/docs/envelope-encryption) (optional);
//! - Automatic refresh secrets from the sources support (optional);
//!
//! ## Example, security considerations and benchmarks:
//! Available at github: https://github.com/abdolence/secret-vault-rs
//!
//! ```

#![allow(unused_parens, clippy::new_without_default)]

mod encryption;
pub use encryption::*;

pub mod errors;
mod secrets_source;
pub use secrets_source::*;

mod simple_sources;
pub use simple_sources::*;

mod vault_store;

mod common_types;
pub use common_types::*;

#[cfg(feature = "encrypted-ring")]
pub mod ring_encryption;

#[cfg(feature = "encrypted-ring")]
mod ring_encryption_support;

#[cfg(feature = "gcloud")]
pub mod gcp;

#[cfg(feature = "aws")]
pub mod aws;

pub type SecretVaultResult<T> = std::result::Result<T, errors::SecretVaultError>;

mod vault;
pub use vault::*;

mod vault_builder;
pub use vault_builder::SecretVaultBuilder;

mod vault_viewer;
pub use vault_viewer::*;

mod vault_auto_refresher;
pub use vault_auto_refresher::*;

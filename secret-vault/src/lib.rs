//! # Secret Vault for Rust
//!
//! Library provides a secure memory-backed storage of secrets coming to your application
//! from external sources:
//!
//! - Google Cloud Secret Manager
//! - Amazon Secrets Manager
//!
//! ## Features
//! - Caching registered secrets in memory from sources.;
//! - Memory encryption using AEAD cryptography (optional);
//! - Memory protection/locking access (optional);
//! - Extensible and strongly typed API to be able to implement any kind of sources;
//!
//! ## Example, security considerations and benchmarks:
//! Available at github: https://github.com/abdolence/secret-vault-rs
//!
//! ```

#![allow(unused_parens, clippy::new_without_default)]

mod allocator;
pub use allocator::*;

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

#[cfg(feature = "memory-protect")]
pub mod locked_allocator;

#[cfg(feature = "encrypted-ring")]
pub mod ring_encryption;

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

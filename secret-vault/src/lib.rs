#![allow(unused_parens)]

mod allocator;
mod encryption;
pub mod errors;
mod storage;

mod common_types;

#[cfg(feature = "locked")]
mod locked_allocator;

#[cfg(feature = "encrypted-ring")]
mod ring_encryption;

pub type SecretVaultResult<T> = std::result::Result<T, errors::SecretVaultError>;

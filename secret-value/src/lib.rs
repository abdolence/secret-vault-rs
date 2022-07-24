//! # Secret Vault Value type
//!
//! Library provides a simple implementation of a secure and serializable (serde and proto) type
//! of any kind of secrets:
//!
//! - Automatically cleaning up its value after destruction in memory.
//! - Prevents leaking in logs and stack traces
//! - Stored as a byte array and suitable not just for string typed secrets
//!
//! # Working with the type:
//!
//! ```ignore
//! use secret_vault_value::*;
//!
//! let secret_value = SecretValue::from("test");
//!
//! // Use `secret_value.ref_sensitive_value()`
//!
//! ```

#![allow(unused_parens)]
#![forbid(unsafe_code)]

mod value;
pub use value::*;

#[cfg(feature = "serde")]
mod value_serde;
#[cfg(feature = "serde")]
pub use value_serde::*;

#[cfg(feature = "proto")]
mod value_proto;
#[cfg(feature = "proto")]
pub use value_proto::*;

#[cfg(feature = "bytes")]
mod bytes_support;
#[cfg(feature = "bytes")]
pub use bytes_support::*;

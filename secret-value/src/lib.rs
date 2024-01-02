//! # Secret Vault Value type
//!
//! Library provides a simple implementation of a secure and serializable (serde and proto) type
//! of any kind of secrets:
//!
//! - Automatically cleaning up its value after destruction in memory.
//! - Prevents leaking in logs and stack traces
//! - Stored as a byte array and suitable for binary secrets;
//! - Introduces additional functions with predicates to control the exposed border;
//!    of exposed secret values and clean-ups: `exposed_in_*`;
//! - Supports deserialization of embedded JSON value in string using `expose_json_value_as`;
//! - Securely encoding/decoding from hex/base64 formats;
//!
//! # Working with the type:
//!
//! ```ignore
//! use secret_vault_value::*;
//!
//! // Creating from string
//! let secret_value: SecretValue = "test".into();
//!
//! // Creating from vec
//! let secret_value: SecretValue = vec![4,2].into();
//!
//! // Creating from BytesMut
//! let secret_value: SecretValue = bytes::BytesMut::from("test").into();
//!
//! // Reading as a string
//! let secret_value: &str = secret_value4.as_sensitive_str();
//!
//! Reading as bytes
//! let secret_value: &[u8] = secret_value.as_sensitive_bytes()
//!
//! // Reading as hex string
//! let secret_value: Zeroizing<String> = secret_value.as_sensitive_hex_str();
//!
//! // Reading as base64 string
//! let secret_value: Zeroizing<String> = secret_value.as_sensitive_base64_str();
//!
//! // Controlling the exposed value with closures/lambdas
//! let your_result = secret_value.exposed_in_as_zstr(|secret_value|{
//!      todo!()
//! });
//!
//! // Controlling the exposed value with async closures/lambdas
//! let your_result = secret_value.exposed_in_as_zstr_async(|secret_value| async {
//!      todo!()
//! }).await;
//!
//! // Deserialize embedded string value from JSON and expose it as zeroizable structure:
//! #[derive(Deserialize, Zeroize)]
//! struct YourType { ... }
//!
//! let your_result_json: YourType = secret_value.expose_json_value_as::<YourType>().unwrap();
//!
//! ```

#![allow(unused_parens, unused_imports)]
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

#[cfg(feature = "hex")]
mod hex_support;
#[cfg(feature = "hex")]
pub use hex_support::*;

#[cfg(feature = "base64")]
mod base64_support;
#[cfg(feature = "base64")]
pub use base64_support::*;

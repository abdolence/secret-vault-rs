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
//!
//! # Working with the type:
//!
//! ```ignore
//! use secret_vault_value::*;
//!
//! // Creating from string
//! let secret_value: SecretValue = "test".into();
//!
//! // Reading as String
//! let secret_value: &str = secret_value4.sensitive_value_to_str()?;
//!
//! // Reading as vector
//! let secret_value: &Vec<u8> = secret_value.ref_sensitive_value();
//!
//! // Reading from BytesMut
//! let secret_value: SecretValue = bytes::BytesMut::from("test").into();
//!
//! // Controlling the exposed value with closures/lambdas
//! let your_result: YourType = secret_value.exposed_in_as_str(|secret_value|{
//!      let some_result: YourType = todo!();
//!      (some_result, secret_value) // Returning back secret_value to zeroize
//! });
//!
//! // Controlling the exposed value with async closures/lambdas
//! let your_result: YourType = secret_value.exposed_in_as_str_async(|secret_value| async {
//!      let some_result: YourType = todo!();
//!      (some_result, secret_value) // Returning back secret_value to zeroize
//! }).await;
//!
//! // Deserialize embedded string value from JSON and expose it as zeroizable structure:
//! #[derive(Deserialize, Zeroize)]
//! struct YourType {
//!     _some_field: String
//! }
//!
//! let your_result_json: YourType = secret_value.expose_json_value_as::<YourType>().unwrap();
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

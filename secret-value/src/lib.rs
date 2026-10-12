//! # Secret value type
//!
//! A secure and serializable type for any kind of secret:
//! - zeroizes its bytes in memory when dropped, using [zeroize](https://docs.rs/zeroize);
//! - prints `***` in `Debug` and `Display`, so it does not leak into logs and panic messages;
//! - stores bytes, so it fits binary secrets too;
//! - lends copies to closures with the `exposed_in_*` methods and zeroizes them afterwards;
//! - parses JSON embedded in a secret with `expose_json_value_as`;
//! - encodes and decodes hex and base64.
//!
//! ```
//! use secret_vault_value::SecretValue;
//!
//! let secret_value: SecretValue = "my-password".into();
//! assert_eq!(format!("{secret_value:?}"), "***");
//!
//! // Borrowing, no copies
//! let password: &str = secret_value.as_sensitive_str();
//! let bytes: &[u8] = secret_value.as_sensitive_bytes();
//!
//! // The copy passed to the closure is zeroized when the closure is done
//! let length = secret_value.exposed_in_as_zstr(|password| password.len());
//!
//! // Async closures work the same way
//! async fn password_length(secret_value: &SecretValue) -> usize {
//!     secret_value
//!         .exposed_in_as_zstr_async(|password| async move { password.len() })
//!         .await
//! }
//! # assert_eq!(password, "my-password");
//! # assert_eq!(bytes, b"my-password");
//! # assert_eq!(length, 11);
//! # let runtime = tokio::runtime::Runtime::new().unwrap();
//! # assert_eq!(runtime.block_on(password_length(&secret_value)), 11);
//! ```
//!
//! # Features
//!
//! - `serde`: `Serialize` and `Deserialize` as a string, and `expose_json_value_as` (brings `serde_json`);
//! - `proto`: `prost::Message`, encoding the value as a `bytes` field;
//! - `bytes`: conversion from `bytes::BytesMut`;
//! - `hex`: hex encoding and decoding;
//! - `base64`: base64 encoding and decoding.

#![warn(missing_docs)]
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

//! # Google Cloud Secret Manager client for Rust
//!
//! Library provides a simple API for Google Cloud Secret Manager to:
//!- Read specified secrets in a simple and secure way;
//!- Caching secrets encrypted in memory to avoid network calls and delays;
//!- Google client based on [gcloud-sdk library](https://github.com/abdolence/gcloud-sdk-rs)
//!that automatically detects tokens or GKE environment;
//!- Models and API to avoid accidentally leaking secrets in logs and stack traces;
//!
//! Examples available at: https://github.com/abdolence/gcloud-secrets-rs/tree/master/src/examples
//!
//! ## Please read security considerations at
//!  https://github.com/abdolence/gcloud-secrets-rs
//!

#![allow(clippy::new_without_default)]

pub mod errors;
mod secrets_reader;
pub use secrets_reader::*;

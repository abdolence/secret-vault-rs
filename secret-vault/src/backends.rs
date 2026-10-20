//! The AEAD backends of kms-aead, under the same names and module path: one zero-sized type per
//! crypto library, each added by its feature and implementing the sealed [`AeadBackend`].
//!
//! The backend is the type parameter of the encryption types and of `TempSecretGenSource`, such
//! as `SecretVaultAeadEncryption<AwsLc>`:
//!
//! - `AwsLc` with the `aws-lc` or `aws-lc-fips` feature;
//! - `Ring` with `ring`;
//! - `RustCrypto` with `rustcrypto`.
//!
//! No type of a crypto library reaches the public API.

pub use kms_aead::backends::AeadBackend;

#[cfg(any(feature = "aws-lc", feature = "aws-lc-fips"))]
pub use kms_aead::backends::AwsLc;
#[cfg(feature = "ring")]
pub use kms_aead::backends::Ring;
#[cfg(feature = "rustcrypto")]
pub use kms_aead::backends::RustCrypto;

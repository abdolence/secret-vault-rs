#[cfg(feature = "ahash-snapshot")]
mod ahash_snapshot;
#[cfg(feature = "ahash-snapshot")]
pub use ahash_snapshot::*;

mod std_hash_snapshot;
pub use std_hash_snapshot::*;

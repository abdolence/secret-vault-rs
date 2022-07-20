[![Cargo](https://img.shields.io/crates/v/secret-vault.svg)](https://crates.io/crates/secret-vault)
[![Cargo](https://img.shields.io/crates/v/secret-vault-value.svg)](https://crates.io/crates/secret-vault-value)
![tests and formatting](https://github.com/abdolence/secret-vault-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/secret-vault-rs/workflows/security%20audit/badge.svg)

# Secret Vault for Rust

Library provides following crates:

## Secret value type
A simple implementation of a secure and serializable (serde and proto) type
of any kind of secrets:
 - Automatically cleaning up its value after destruction in memory using [zeroize](https://docs.rs/zeroize/latest/zeroize/)
 - Prevents leaking in logs and stack traces
 - Stored as a byte array and suitable not just for string typed secrets

### Working with the type:

```rust
 use secret_vault_value::*;

 let secret_value = SecretValue::from("test");
  // Use `secret_value.ref_sensitive_value()`
```

## Secret Vault 

Library provides a secure memory-backed storage of secrets coming to your application from external sources:
 - Google Cloud Secret Manager
 - Amazon Secrets Manager

### Features
- Reading/caching registered secrets in memory from defined sources;
- Memory encryption using AEAD cryptography (optional);
- Memory protection/locking access (optional);
- Extensible and strongly typed API to be able to implement any kind of sources;

## Quick start

Cargo.toml:
```toml
[dependencies]
secret-vault = { version = "0.1.<x>", features=["..."] }
secret-vault-type = { version = "0.1.<x>", features=["..."] }
```
See security consideration below about versioning.

### Available optional features for Secret Vault:
- `gcloud-secretmanager` for Google Secret Manager support
- `aws-secretmanager` for Amazon Secret Manager support
- `memory-protect` for memory protection support
- `encrypted-ring` for encryption support
- `serde` for serde serialization support

### Available optional features for secret value type:
- `serde` for serde serialization support
- `prost` for protobuf serialization support


## Example for GCP with memory protection and encryption:
```rust

// Describing secrets and marking them non-required
// since this is only example and they don't exist in your project
let secret1 = SecretVaultRef::new("test-secret1".into()).with_required(false);
let secret2 = SecretVaultRef::new("test-secret2".into())
    .with_secret_version("1".into())
    .with_required(false);

// Building the vault
let mut vault = SecretVaultBuilder::with_source(
    gcp::GoogleSecretManagerSource::new(&config_env_var("PROJECT_ID")?).await?,
)
    .with_encryption(ring_encryption::SecretVaultRingAeadEncryption::new()?)
    .with_memory_protection(locked_allocator::SecretVaultMemoryProtectAllocator::new())
    .build()?;

// Registering your secrets and receiving them from source
vault
    .with_secrets_refs(vec![&secret1, &secret2])
    .refresh()
    .await?;

// Reading the secret values
let secret_value: Option<Secret> = vault.get_secret_by_ref(&secret1)?;

println!("Received secret: {:?}", secret);

// Using the Viewer API to share only methods able to read secrets
let vault_viewer = vault.viewer();
vault_viewer.get_secret_by_ref(&secret2)?;

// Using the Snapshot API to be able to share the instance without having to store `vault`
// Since this point `vault` is not available anymore to borrow and update secrets
let vault_snapshot = vault.snapshot();
vault_snapshot.get_secret_by_ref(&secret2)?;

```

All examples available at [secret-vault/examples](secret-vault/examples) directory.

To run this example use with environment variables:
```
# PROJECT_ID=<your-google-project-id> cargo run --example gcloud_secret_manager_vault
```

## Security considerations and risks

### OSS
Open source code is created through voluntary collaboration of software developers.
The original authors license the code so that anyone can see it, modify it, and
distribute new versions of it.
You should manage all OSS using the same procedures and tools that you use for
commercial products. As always, train your employees on
cyber security best practices that can help them securely 
use and manage software products.
You should not solely rely on individuals, especially on the projects like this
reading sensitive information.

### Versioning
Please don't use broad version dependency management not to include
a new version of dependency automatically without your auditing the changes.

### Protect your secrets in GCP/AWS using IAM and service accounts
Don't expose all of your secrets to the apps. 
Use IAM and different service accounts to give access only on as-needed basis.

### Zeroing, protecting memory and encryption don't provide 100% safety
There are still allocations on the protocol layers, there is
a session secret key available in memory, privileged users on OS still
have broad access, etc.
So don't consider this is a completely safe solution for all possible attacks.
Mitigation some of the attacks is not possible without implementing
additional support on hardware/OS level (such as Intel SGX project, for instance).

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov

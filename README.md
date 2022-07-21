[![Cargo](https://img.shields.io/crates/v/secret-vault.svg)](https://crates.io/crates/secret-vault)
[![Cargo](https://img.shields.io/crates/v/secret-vault-value.svg)](https://crates.io/crates/secret-vault-value)
![tests and formatting](https://github.com/abdolence/secret-vault-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/secret-vault-rs/workflows/security%20audit/badge.svg)

# Secret Vault for Rust

Library provides following crates:

- General secret value type - a simple implementation of a secure and serializable (serde and proto) type
  of any kind of secrets. Documentation located [here](secret-value/README.md).
- Secret vault - a library provides a secure memory-backed storage of the application secrets to store them secure way.
  Documentation is below.

## Secret Vault 

Library provides the native support for the secrets coming to your application from external sources:
 - Google Cloud Secret Manager
 - Amazon Secrets Manager

## Features
- Reading/caching registered secrets in memory from defined sources;
- Memory encryption using AEAD cryptography (optional);
- Memory encryption using Google/AWS KMS [envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption) (optional);
- Automatic refresh secrets from the sources support (optional);
- Extensible and strongly typed API to be able to implement any kind of sources;


## Quick start

Cargo.toml:
```toml
[dependencies]
secret-vault = { version = "0.4.<x>", features=["..."] }
secret-vault-type = { version = "0.1.<x>", features=["..."] }
```
See security consideration below about versioning.

### Available optional features for Secret Vault:
- `gcloud-secretmanager` for Google Secret Manager support
- `aws-secretmanager` for Amazon Secret Manager support
- `encrypted-ring` for encryption support
- `gcloud-kms-encryption` for Google KMS envelope encryption support
- `serde` for serde serialization support

### Available optional features for secret value type:
- `serde` for serde serialization support
- `prost` for protobuf serialization support


## Example for GCP with AEAD encryption:

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
    .build()?;

// Registering your secrets and receiving them from source
vault
    .register_secrets_refs(vec![&secret1, &secret2])
    .refresh()
    .await?;

// Reading the secret values
let secret: Option<Secret> = vault.get_secret_by_ref(&secret1).await?;
// Or if you require it available
let secret: Secret = vault.require_secret_by_ref(&secret1).await?;

println!("Received secret: {:?}", secret);

// Using the Viewer API to share only methods able to read secrets
let vault_viewer = vault.viewer();
vault_viewer.get_secret_by_ref(&secret2).await?;

```

To run this example use with environment variables:
```
# PROJECT_ID=<your-google-project-id> cargo run --example gcloud_secret_manager_vault
```

All examples available at [secret-vault/examples](secret-vault/examples) directory.

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

## Performance details

The comparison between reading performance of encrypted and non-encrypted vault:

```
read-secrets-perf-simple-vault
                        time:   [126.47 ns 126.70 ns 126.99 ns]

read-secrets-perf-encrypted-vault
                        time:   [292.15 ns 292.97 ns 293.95 ns]
```

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov

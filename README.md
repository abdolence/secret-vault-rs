[![Cargo](https://img.shields.io/crates/v/secret-vault.svg)](https://crates.io/crates/secret-vault)
[![Cargo](https://img.shields.io/crates/v/secret-vault-value.svg)](https://crates.io/crates/secret-vault-value)
![tests and formatting](https://github.com/abdolence/secret-vault-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/secret-vault-rs/workflows/security%20audit/badge.svg)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)
![license](https://img.shields.io/github/license/abdolence/secret-vault-rs)


# Secret Vault for Rust

Library provides the following crates:

- General secret value type - a simple implementation of a secure and serializable (serde and proto) type
  of any kind of secrets. Documentation located [here](secret-value/README.md).
- Secret vault - a library provides a memory-backed storage for the application secrets integrated with external source of secrets.
  Documentation is below.

## Secret Vault 

Library provides the native support for the secrets coming to your application from external sources:
 - Google Cloud Secret Manager
 - Amazon Secrets Manager

## Features
- Reading/caching registered secrets in memory from defined sources;
- Memory encryption using AEAD cryptography (optional);
- Automatic refresh secrets from the sources support (optional);
- Extensible and strongly typed API to be able to implement any kind of sources;
- Memory encryption using Google/AWS KMS [envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption) (optional);


## Quick start

Cargo.toml:
```toml
[dependencies]
secret-vault = { version = "0.10.<x>", features=["..."] }
secret-vault-type = { version = "0.3.<x>", features=["..."] }
```
See security consideration below about versioning.

### Available optional features for Secret Vault:
- `gcp-secretmanager` for Google Secret Manager support
- `aws-secretmanager` for Amazon Secret Manager support
- `ring-aead-encryption` for encryption support using Ring AEAD
- `gcp-kms-encryption` for Google KMS envelope encryption support
- `aws-kms-encryption` for Amazon KMS envelope encryption support
- `serde` for serde serialization support

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
    gcp::GcpSecretManagerSource::new(&config_env_var("PROJECT_ID")?).await?,
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
a new version of dependency automatically without auditing the changes.

### Protect your secrets in GCP/AWS using IAM and service accounts
Don't expose all of your secrets to the apps. 
Use IAM and different service accounts to give access only on as-needed basis.

### Zeroing, protecting memory and encryption don't provide 100% safety
There are still allocations on the protocol layers (such as the official Amazon SDK, for instance), 
there is a session secret key available in memory without KMS, etc.

So don't consider this is a completely safe solution for all possible attacks.
The mitigation some of the attacks is not possible without implementing
additional support on hardware/OS level (such as Intel SGX project, for instance).

In general, consider this as one small additional effort to mitigate some risks,
but keep in mind this is not the only solution you should rely on.

The most secure setup/config at the moment available is:
- GCP Secret Manager + KMS enveloper encryption and AEAD

because in case of GCP there are additional effort in Google Cloud SDK provided integration with this library.
One of the unexpected side-effects of not having the official SDK for Rust from Google.

## Performance details

The comparison between reading performance of encrypted and non-encrypted vault:

```
read-secrets-perf-simple-vault
                        time:   [126.47 ns 126.70 ns 126.99 ns]

read-secrets-perf-encrypted-vault
                        time:   [292.15 ns 292.97 ns 293.95 ns]
```

## Rotating application secrets strategy without downtime
This is mostly application specific area, but general idea is
to have at least two version of secrets:

- Current/latest version of secret which will be used for the new transactions/requests/data
  in your application.
- Previous version which still need to be valid to interact.

Then you have two options for configuration/version management:

- Use some configuration in your app that contains those versions and redeploy your app when you need to rotate.
  That means it will trigger refreshing all secrets at the start.
  Recommended for most of the cases, since this is more auditable and declarative.
- Updating automatically secrets and their versions using `SecretVaultAutoRefresher`
  (or your own implementation) without redeploys.

## Making `SecretVaultRef` available globally
It is convenient to make those references globally available inside your apps since
they don't contain any sensitive information.
To make it easy consider using crates such as `lazy_static` or `once_cell`:

```rust
use once_cell::sync::Lazy;

pub static MY_SECRET_REF: Lazy<SecretVaultRef> = Lazy::new(|| {
   SecretVaultRef::new("my-secret".into())
});
```

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov

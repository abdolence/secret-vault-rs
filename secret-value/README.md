[![Cargo](https://img.shields.io/crates/v/secret-vault-value.svg)](https://crates.io/crates/secret-vault-value)
![tests and formatting](https://github.com/abdolence/secret-vault-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/secret-vault-rs/workflows/security%20audit/badge.svg)

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

## Quick start

Cargo.toml:
```toml
[dependencies]
secret-vault-type = { version = "0.1.<x>", features=["..."] }
```
See security consideration below about versioning.

### Available optional features for secret value type:
- `serde` for serde serialization support
- `prost` for protobuf serialization support


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

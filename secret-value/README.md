[![Cargo](https://img.shields.io/crates/v/secret-vault-value.svg)](https://crates.io/crates/secret-vault-value)
![tests and formatting](https://github.com/abdolence/secret-vault-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/secret-vault-rs/workflows/security%20audit/badge.svg)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)
![licence](https://img.shields.io/github/license/abdolence/secret-vault-rs)

## Secret value type
A secure and serialisable type for any kind of secret:
 - Zeroises its bytes in memory when dropped, using [zeroize](https://docs.rs/zeroize/latest/zeroize/);
 - Prints `***` in `Debug` and `Display`, so it does not leak into logs and panic messages;
 - Stores bytes, so it fits binary secrets too;
 - Lends copies to closures with the `exposed_in_*` methods and zeroises them afterwards;
 - Parses JSON embedded in a secret with `expose_json_value_as`;
 - Encodes and decodes hex and base64.

### Working with the type

```rust
use secret_vault_value::SecretValue;

let secret_value: SecretValue = "my-password".into();
assert_eq!(format!("{secret_value:?}"), "***");

// Borrowing, no copies
let password: &str = secret_value.as_sensitive_str();
let bytes: &[u8] = secret_value.as_sensitive_bytes();

// The copy passed to the closure is zeroised when the closure is done
let length = secret_value.exposed_in_as_zstr(|password| password.len());

// Async closures work the same way
async fn password_length(secret_value: &SecretValue) -> usize {
    secret_value
        .exposed_in_as_zstr_async(|password| async move { password.len() })
        .await
}
```

Full example with hex, base64, JSON, `BytesMut` and protobuf available [here](https://github.com/abdolence/secret-vault-rs/blob/master/secret-value/examples/simple.rs):
```sh
cargo run -p secret-vault-value --example simple --all-features
```

## Quick start

Cargo.toml:
```toml
[dependencies]
secret-vault-value = { version = "1.0", features = ["..."] }
```
See security consideration below about versioning.

### Available optional features for secret value type:
- `serde` for serde serialisation support, it also brings `serde_json` for `expose_json_value_as`;
- `proto` for protobuf serialisation support;
- `bytes` for `BytesMut` conversion support;
- `hex` for hex conversion support;
- `base64` for base64 conversion support.

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

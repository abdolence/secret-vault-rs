[![Cargo](https://img.shields.io/crates/v/gcloud-secrets.svg)](https://crates.io/crates/firestore)
![tests and formatting](https://github.com/abdolence/gcloud-secrets-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/gcloud-secrets-rs/workflows/security%20audit/badge.svg)

# Google Cloud Secret Manager client for Rust

Library provides a simple API for Google Cloud Secret Manager to:
- Read specified secrets in a simple and secure way; 
- Caching secrets encrypted in memory to avoid network calls and delays;
- Google client based on [gcloud-sdk library](https://github.com/abdolence/gcloud-sdk-rs) 
  that automatically detects tokens or GKE environment;
- Models and API to avoid accidentally leaking secrets in logs and stack traces;
- Securely zero memory using [zeroize](https://docs.rs/zeroize/latest/zeroize/)

## Quick start

Cargo.toml:
```toml
[dependencies]
gcloud-secret-manager = "0.1.<x>"
```
See security consideration below about versioning.

Example code:
```rust

    // Create an instance
    let db = FirestoreDb::new(&config_env_var("PROJECT_ID")?).await?;

    const TEST_COLLECTION_NAME: &'static str = "test";

    let my_struct = MyTestStructure {
        some_id: "test-1".to_string(),
        some_string: "Test".to_string(),
        some_num: 42,
    };

```

All examples available at examples directory.

To run example use with environment variables:
```
# PROJECT_ID=<your-google-project-id> cargo run --example simple
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

### Auditing source code
This library intentionally doesn't include a lot of source files and any functionality except reading and caching secrets
to make your audit simple.

### Protect your secrets in GCP using IAM and service accounts
Don't expose all of your secrets to the apps. Use IAM and different service accounts to give access only on
as-needed basis.

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov

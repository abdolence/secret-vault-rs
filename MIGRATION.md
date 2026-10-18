# Migrating from 2.x to 3.1

secret-vault 3.1 is built on kms-aead 0.30 and no longer depends on ring.
The encryption runs on a crypto library a feature compiles in, and a type parameter of the encryption selects it: `Ring`, `AwsLc` or `RustCrypto` of `secret_vault::backends`.
The vault keeps values in memory only, so no stored data needs to be migrated.

Users of 3.0 follow the same guide: every 3.0 API that 3.1 changes is listed here, and the names that only 3.0 had are marked as such.

## Minimum Rust version

The minimum supported Rust version is 1.99, the version kms-aead 0.30 needs.

## Features

- `ring-aead-encryption` is replaced by the backend features `ring`, `aws-lc`, `aws-lc-fips` and `rustcrypto`, and a build may enable any number of them;
- the KMS encryption features (`gcp-kms`, `gcp-kms-base`, `aws-kms-encryption`, `azure-kms*` and `hashicorp-vault-transit*`) no longer enable ring and need a backend feature, without one kms-aead fails to compile with `kms-aead needs a crypto backend for its KMS providers`;
- `gcp-secretmanager` no longer enables ring, enable a backend feature with it for the encryption of stored values;
- `gcp-kms` no longer selects a TLS root store, enable `gcp`, `gcp-tls-roots` or `gcp-tls-webpki` with it, without one gcloud-sdk fails to compile with `cannot find ClientTlsConfig in tonic::transport`;
- `gcp-kms-tls-roots` and `gcp-kms-webpki` are removed, use `gcp-kms` with `gcp-tls-roots` or `gcp-tls-webpki`;
- `aws-kms` is removed, use `aws-kms-encryption`;
- `kms` and `kms-aead`, the feature of the optional dependency, are removed, the backend and KMS encryption features enable kms-aead themselves;
- `TempSecretGenSource` needs a backend feature instead of `ring-aead-encryption`.

## Secret names and refs

`SecretName`, `SecretNamespace` and `SecretVersion` hold a `Cow<'static, str>`, so they can be created in `const` and `static` items:

- `value()` returns `&str` instead of `&String`, use `.to_string()` where a `String` is needed;
- `.value().as_str()` no longer compiles (`str::as_str` is unstable, error E0658), drop the `.as_str()`;
- `into_value()` is removed, use `.value().to_owned()` or `.to_string()` instead;
- `AsRef<str>` is removed, pass `.value()` where a function takes `impl AsRef<str>`;
- `value()` is an inherent method, since the types no longer implement `rvstruct::ValueStruct`, so remove `use rvstruct::ValueStruct` unless it is needed for `EncryptedSecretValue`;
- `SecretVaultRef::new`, `with_required`, `with_auto_refresh` and `with_allow_in_snapshots` are `const fn`.

Creating the types with `new()`, `"name".into()`, `String::into()` and `parse()`, and formatting them with `Display`, work as before.

## AEAD encryption

- `ring_encryption::SecretVaultRingAeadEncryption::new()` is `aead_encryption::SecretVaultAeadEncryption::<Ring>::new()`, or another backend;
- `SecretVaultRingAeadEncryption::with_algorithm(&ring::aead::CHACHA20_POLY1305)` is `SecretVaultAeadEncryption::<Ring>::with_algorithm(AeadAlgorithm::ChaCha20Poly1305)`;
- the default algorithm stays AES-256-GCM;
- the backend types `Ring`, `AwsLc` and `RustCrypto` and the `AeadBackend` trait are in the `backends` module, the path kms-aead 0.30 uses, so `use secret_vault::backends::AwsLc;`.

## KMS envelope encryption

- `GcpKmsEnvelopeEncryption` and `AwsKmsEnvelopeEncryption` are aliases of `kms_encryption::SecretVaultKmsEnvelopeEncryption<P, B>` with the KMS provider `P` and the backend `B`, and take the backend as a type parameter, for example `gcp::GcpKmsEnvelopeEncryption::<AwsLc>::new(&kms_key_ref).await?`;
- the encryptions for Azure Key Vault and HashiCorp Vault Transit, `azure::AzureKmsEnvelopeEncryption<B>` and `hashicorp::HcVaultTransitEnvelopeEncryption<B>`, take the backend the same way, and their constructors are not `async`, so the `.await` of 3.0 code goes;
- the 3.0 names `VaultTransitEnvelopeEncryption`, `VaultTransitKeyRef`, `VaultTransitProviderOptions` and `VaultTransitToken` are `HcVaultTransitEnvelopeEncryption`, `HcVaultTransitKeyRef`, `HcVaultTransitProviderOptions` and `HcVaultTransitToken`, the names of kms-aead 0.30;
- the AEAD encryption stores its values in kms-aead's `Bare` format and the KMS envelope encryption in its `Envelope` format, Tink's KMS envelope format.

## Custom encryption implementations

- the `From` conversions between `EncryptedSecretValue` and the kms-aead `CipherText` and `CipherTextWithEncryptedKey` are replaced by one pair for kms-aead 0.30's `Encrypted<SecretValue, F>` in any format `F`: `From<Encrypted<SecretValue, F>>` for `EncryptedSecretValue`, and `TryFrom<EncryptedSecretValue>` for `Encrypted<SecretValue, F>`, which checks the bytes against the layout of `F` and fails with `INVALID_CIPHER_TEXT_FORMAT` outside it, so custom `SecretVaultEncryption` implementations write `Encrypted::<SecretValue, Bare>::try_from(value)?` where they wrote `value.into()`;
- `SecretVaultKey::to_aad()` returns `&[u8]` instead of `&String`, pass `key.to_aad()` to kms-aead;
- implementations built on kms-aead types move to kms-aead 0.30 as well.

## Errors

- the code of an `EncryptionError` from kms-aead is the kms-aead error code, such as `DECRYPT` or `IncorrectKeyException` from AWS KMS, instead of the `Debug` text of the error;
- a kms-aead `NetworkError`, a KMS that could not be reached, timed out or throttled, is a `SecretVaultError::NetworkError` instead of an `EncryptionError`, with the same code, and it may be retried; permission, not-found and invalid-key failures stay `EncryptionError`s;
- a kms-aead `SystemError`, invalid provider options or a KMS client that cannot be built, is a `SecretVaultError::SystemError` instead of an `EncryptionError`, with the same code;
- the `From` conversion of the AWS SDK `SdkError` of `aws-sdk-kms` into `SecretVaultError` is removed, and with it the direct `aws-sdk-kms` dependency of `aws-kms-encryption`.

## Other changes

- `generate_secret_value` is removed, it took a ring `SystemRandom`;
- `TempSecretGenSource` takes the backend that generates the secrets as a type parameter, `TempSecretGenSource::<AwsLc>::with_options(options)?`, and with `aws-lc-fips` they come from the DRBG of the FIPS module;
- a printable temporary secret with an odd `key_len` has `key_len` characters instead of one less;
- `EncryptedSecretValue` prints `***` through `Debug` instead of its bytes;
- the defaults of the options are public constants, such as `TempSecretOptions::DEFAULT_PRINTABLE` and `hashicorp::HashiCorpVaultSourceOptions::DEFAULT_TIMEOUT`.

# Migrating from 3.0 to 3.1

secret-vault 3.1 is built on kms-aead 0.30 and no longer depends on ring.
The encryption runs on a crypto library a feature compiles in, and a type parameter of the encryption selects it: `Ring`, `AwsLc` or `RustCrypto`.
The vault keeps values in memory only, so no stored data needs to be migrated.

## Features

- `ring-aead-encryption` is replaced by the backend features `ring`, `aws-lc`, `aws-lc-fips` and `rustcrypto`, and a build may enable any number of them;
- the KMS encryption features (`gcp-kms`, `gcp-kms-base`, `aws-kms-encryption`, `azure-kms*` and `hashicorp-vault-transit*`) no longer enable ring and need a backend feature, without one kms-aead fails to compile with `kms-aead needs a crypto backend for its KMS providers`;
- `gcp-secretmanager` and `gcp-secretmanager-base` no longer enable ring;
- `kms` and `kms-aead`, the feature of the optional dependency, are removed, the backend and KMS encryption features enable kms-aead themselves;
- `aws-kms` is removed, use `aws-kms-encryption`;
- `gcp-kms-tls-roots` and `gcp-kms-webpki` are removed, use `gcp-kms` with `gcp-tls-roots` or `gcp-tls-webpki`;
- `TempSecretGenSource` needs a backend feature instead of `ring-aead-encryption`.

## AEAD encryption

- `ring_encryption::SecretVaultRingAeadEncryption::new()` is `aead_encryption::SecretVaultAeadEncryption::<Ring>::new()`, or another backend;
- `SecretVaultRingAeadEncryption::with_algorithm(&ring::aead::CHACHA20_POLY1305)` is `SecretVaultAeadEncryption::<Ring>::with_algorithm(AeadAlgorithm::ChaCha20Poly1305)`;
- the default algorithm stays AES-256-GCM.

## KMS envelope encryption

- `SecretVaultKmsEnvelopeEncryption<P>` is `SecretVaultKmsEnvelopeEncryption<P, B>` with the backend `B`, and so `GcpKmsEnvelopeEncryption`, `AwsKmsEnvelopeEncryption`, `AzureKmsEnvelopeEncryption` and the Transit encryption take the backend as a type parameter, for example `gcp::GcpKmsEnvelopeEncryption::<AwsLc>::new(&kms_key_ref).await?`;
- the Azure and Transit constructors are not `async`, remove the `.await`;
- `VaultTransitEnvelopeEncryption`, `VaultTransitKeyRef`, `VaultTransitProviderOptions` and `VaultTransitToken` are renamed to `HcVaultTransitEnvelopeEncryption`, `HcVaultTransitKeyRef`, `HcVaultTransitProviderOptions` and `HcVaultTransitToken`, the names of kms-aead 0.30;
- `kms_encryption::LocalKmsEnvelopeEncryption<B>` is new: envelope encryption with a key encryption key the process holds.

## Other changes

- `generate_secret_value` is removed, it took a ring `SystemRandom`;
- `TempSecretGenSource` takes the backend that generates the secrets as a type parameter, `TempSecretGenSource::<AwsLc>::with_options(options)?`, and with `aws-lc-fips` they come from the DRBG of the FIPS module;
- a printable temporary secret with an odd `key_len` has `key_len` characters instead of one less;
- the code of an `EncryptionError` from kms-aead is the kms-aead error code, such as `DECRYPT` or `IncorrectKeyException` from AWS KMS, instead of the `Debug` text of the error;
- `SecretVaultKey::to_aad()` returns `&[u8]` instead of `Cow<'static, [u8]>`, `&key.to_aad()` still compiles where a `&[u8]` is expected;
- the `From` conversions between `EncryptedSecretValue` and the kms-aead `CipherText` and `CipherTextWithEncryptedKey` are on the kms-aead 0.30 types, so custom `SecretVaultEncryption` implementations using them move to kms-aead 0.30 as well.

# Migrating from 2.x to 3.0

`SecretName`, `SecretNamespace` and `SecretVersion` hold a `Cow<'static, str>` in 3.0,
so they can be created in `const` and `static` items. Changes visible to callers:

- `value()` returns `&str` instead of `&String`, use `.to_string()` where a `String` is needed;
- `.value().as_str()` no longer compiles (`str::as_str` is unstable, error E0658), drop the `.as_str()`;
- `into_value()` is removed, use `.value().to_owned()` or `.to_string()` instead;
- `AsRef<str>` is removed, pass `.value()` where a function takes `impl AsRef<str>`;
- `value()` is an inherent method, since the types no longer implement `rvstruct::ValueStruct`,
  so remove `use rvstruct::ValueStruct` unless it is needed for `EncryptedSecretValue`;
- `SecretVaultKey::to_aad()` returns `Cow<'static, [u8]>` instead of `&String`,
  so custom `SecretVaultEncryption` implementations pass `&key.to_aad()` to kms-aead,
  and the ones using the `From<kms_aead::…>` conversions to secret-vault types move to kms-aead 0.29 as well;
- `SecretVaultRef::new`, `with_required`, `with_auto_refresh` and `with_allow_in_snapshots` are `const fn`.

Creating the types with `new()`, `"name".into()`, `String::into()` and `parse()`, and formatting them with `Display`, work as before.

## GCP KMS features

`gcp-kms` no longer selects a TLS root store, enable `gcp`, `gcp-tls-roots` or `gcp-tls-webpki` with it; without one gcloud-sdk fails to compile with `cannot find ClientTlsConfig in tonic::transport`.

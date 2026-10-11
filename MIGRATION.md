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
  so custom `SecretVaultEncryption` implementations pass `&key.to_aad()` to kms-aead;
- `SecretVaultRef::new`, `with_required`, `with_auto_refresh` and `with_allow_in_snapshots` are `const fn`.

Creating the types with `new()`, `"name".into()`, `String::into()` and `parse()`, and formatting them with `Display`, work as before.

## GCP TLS features

GCP features select the rustls crypto provider separately from the TLS root store:

- `gcp-tls-roots` and `gcp-tls-webpki` need `gcp-tls-aws-lc-rs`, the provider 2.x always used, or `gcp-tls-no-provider` to use the provider your application installs;
- `gcp-secretmanager` no longer enables the aws-lc-rs provider of gcloud-sdk by itself;
- `gcp`, `gcp-kms`, `gcp-kms-tls-roots` and `gcp-kms-webpki` include `gcp-tls-aws-lc-rs` and work as before;
- `gcp-kms-webpki` is renamed to `gcp-kms-tls-webpki`, the old name still works.

| 2.x features | 3.0 features |
|---|---|
| `gcp-secretmanager`, `gcp-tls-roots` | `gcp-secretmanager`, `gcp` (or `gcp-tls-roots`, `gcp-tls-aws-lc-rs`) |
| `gcp-secretmanager`, `gcp-tls-webpki` | `gcp-secretmanager`, `gcp-tls-webpki`, `gcp-tls-aws-lc-rs` |
| `gcp-kms-webpki` | `gcp-kms-tls-webpki` |

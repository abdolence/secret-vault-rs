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

use jiff::{SignedDuration, Timestamp};
use rsb_derive::*;
use secret_vault_value::SecretValue;
use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// The name a source knows a secret by: a secret ID in a cloud secret manager,
/// an environment variable, a file name.
///
/// A name built with [`SecretName::from_static`] and one built from a `String`
/// with the same text are equal and hash the same.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SecretName(Cow<'static, str>);

impl SecretName {
    pub const fn new(value: String) -> Self {
        Self(Cow::Owned(value))
    }

    /// Builds a name in a `const` context, for a [`SecretVaultRef`] declared as a `static`.
    pub const fn from_static(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretName {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&String> for SecretName {
    fn from(value: &String) -> Self {
        Self::new(value.clone())
    }
}

impl From<&str> for SecretName {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl FromStr for SecretName {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(value.into())
    }
}

impl Display for SecretName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.value(), f)
    }
}

/// Selects the source of a secret when the vault reads from
/// [`MultipleSecretsSources`](crate::MultipleSecretsSources).
///
/// A namespace built with [`SecretNamespace::from_static`] and one built from a
/// `String` with the same text are equal and hash the same.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SecretNamespace(Cow<'static, str>);

impl SecretNamespace {
    pub const fn new(value: String) -> Self {
        Self(Cow::Owned(value))
    }

    /// Builds a namespace in a `const` context, for a [`SecretVaultRef`] declared as a `static`.
    pub const fn from_static(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretNamespace {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&String> for SecretNamespace {
    fn from(value: &String) -> Self {
        Self::new(value.clone())
    }
}

impl From<&str> for SecretNamespace {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl FromStr for SecretNamespace {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(value.into())
    }
}

impl Display for SecretNamespace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.value(), f)
    }
}

/// A version of a secret as its source names it, such as `AWSCURRENT` or `3`.
///
/// A version built with [`SecretVersion::from_static`] and one built from a
/// `String` with the same text are equal and hash the same.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SecretVersion(Cow<'static, str>);

impl SecretVersion {
    pub const fn new(value: String) -> Self {
        Self(Cow::Owned(value))
    }

    /// Builds a version in a `const` context, for a [`SecretVaultRef`] declared as a `static`.
    pub const fn from_static(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretVersion {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&String> for SecretVersion {
    fn from(value: &String) -> Self {
        Self::new(value.clone())
    }
}

impl From<&str> for SecretVersion {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl FromStr for SecretVersion {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(value.into())
    }
}

impl Display for SecretVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.value(), f)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SecretVaultRef {
    pub key: SecretVaultKey,

    pub required: bool,
    pub auto_refresh: bool,
    pub allow_in_snapshots: bool,
    pub predefined_labels: Vec<SecretMetadataLabel>,
}

impl SecretVaultRef {
    pub const fn new(secret_name: SecretName) -> Self {
        Self::from_key(SecretVaultKey::from_parts(secret_name, None, None))
    }

    /// A required reference to the secret under `key`, not refreshed automatically,
    /// not allowed in snapshots and without predefined labels, as [`SecretVaultRef::new`] makes it.
    ///
    /// With [`SecretVaultKey::from_parts`] this declares a reference with a version or
    /// a namespace as a `static`.
    pub const fn from_key(key: SecretVaultKey) -> Self {
        Self {
            key,
            required: true,
            auto_refresh: false,
            allow_in_snapshots: false,
            predefined_labels: Vec::new(),
        }
    }

    pub fn with_secret_version(self, value: SecretVersion) -> Self {
        Self {
            key: self.key.with_secret_version(value),
            ..self
        }
    }

    pub fn opt_secret_version(self, value: Option<SecretVersion>) -> Self {
        Self {
            key: self.key.opt_secret_version(value),
            ..self
        }
    }

    pub fn with_namespace(self, value: SecretNamespace) -> Self {
        Self {
            key: self.key.with_namespace(value),
            ..self
        }
    }

    pub fn opt_namespace(self, value: Option<SecretNamespace>) -> Self {
        Self {
            key: self.key.opt_namespace(value),
            ..self
        }
    }

    // The flags are assigned in place because struct update syntax (`..self`) is
    // rejected in a `const fn` on a type that needs dropping.
    pub const fn with_required(mut self, value: bool) -> Self {
        self.required = value;
        self
    }

    pub const fn with_auto_refresh(mut self, value: bool) -> Self {
        self.auto_refresh = value;
        self
    }

    pub const fn with_allow_in_snapshots(mut self, value: bool) -> Self {
        self.allow_in_snapshots = value;
        self
    }

    pub fn add_predefined_label(self, label: SecretMetadataLabel) -> Self {
        let mut predefined_labels = self.predefined_labels;
        predefined_labels.push(label);
        Self {
            predefined_labels,
            ..self
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretVaultKey {
    pub secret_name: SecretName,
    pub secret_version: Option<SecretVersion>,
    pub namespace: Option<SecretNamespace>,
}

impl SecretVaultKey {
    /// Builds a key in a `const` context, for a [`SecretVaultRef`] declared as a `static`
    /// with [`SecretVaultRef::from_key`].
    pub const fn from_parts(
        secret_name: SecretName,
        secret_version: Option<SecretVersion>,
        namespace: Option<SecretNamespace>,
    ) -> Self {
        // The `with_*` builders cannot be `const`: replacing an `Option` field drops
        // its previous value, which a `const fn` may not do.
        Self {
            secret_name,
            secret_version,
            namespace,
        }
    }

    /// The additional authenticated data for a value encrypted under this key: the
    /// bytes of the secret name, the same whichever way the name was built.
    pub fn to_aad(&self) -> Cow<'static, [u8]> {
        // kms-aead takes the AAD as an owned `'static` type, so a `&[u8]` borrowed
        // from `self` will not do; a name from a `static` still costs no allocation.
        match &self.secret_name.0 {
            Cow::Borrowed(name) => Cow::Borrowed(name.as_bytes()),
            Cow::Owned(name) => Cow::Owned(name.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretMetadataLabel {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretMetadataAnnotation {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct SecretMetadata {
    #[default = "Timestamp::now()"]
    pub cached_at: Timestamp,
    pub key: SecretVaultKey,
    pub labels: Option<Vec<SecretMetadataLabel>>,
    pub annotations: Option<Vec<SecretMetadataAnnotation>>,
    pub description: Option<String>,
    pub expiration: Option<SecretExpiration>,
    pub version: Option<SecretVersion>,
    pub created_at: Option<Timestamp>,
    pub updated_at: Option<Timestamp>,
}

impl SecretMetadata {
    pub fn create_from_ref(secret_ref: &SecretVaultRef) -> Self {
        let mut result = SecretMetadata::new(secret_ref.key.clone());
        if !secret_ref.predefined_labels.is_empty() {
            result.labels(secret_ref.predefined_labels.clone());
        }
        result
    }

    pub fn add_label(&mut self, label: SecretMetadataLabel) -> &Self {
        if let Some(labels) = &mut self.labels {
            labels.push(label);
        } else {
            self.labels = Some(vec![label]);
        }
        self
    }

    pub fn add_annotation(&mut self, annotation: SecretMetadataAnnotation) -> &Self {
        if let Some(annotations) = &mut self.annotations {
            annotations.push(annotation);
        } else {
            self.annotations = Some(vec![annotation]);
        }
        self
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct Secret {
    pub value: SecretValue,
    pub metadata: SecretMetadata,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SecretExpiration {
    ExpireTime(Timestamp),
    Ttl(SignedDuration),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, RandomState};

    static DATABASE_PASSWORD: SecretVaultRef =
        SecretVaultRef::from_key(SecretVaultKey::from_parts(
            SecretName::from_static("database-password"),
            Some(SecretVersion::from_static("2")),
            Some(SecretNamespace::from_static("aws")),
        ))
        .with_required(false)
        .with_auto_refresh(true)
        .with_allow_in_snapshots(true);

    #[test]
    fn static_ref_equals_and_hashes_as_the_same_ref_built_at_runtime() {
        let runtime_ref = SecretVaultRef::new(String::from("database-password").into())
            .with_secret_version("2".into())
            .with_namespace(String::from("aws").into())
            .with_required(false)
            .with_auto_refresh(true)
            .with_allow_in_snapshots(true);

        assert_eq!(DATABASE_PASSWORD, runtime_ref);
        let hasher = RandomState::new();
        assert_eq!(
            hasher.hash_one(&DATABASE_PASSWORD),
            hasher.hash_one(&runtime_ref)
        );
    }
}

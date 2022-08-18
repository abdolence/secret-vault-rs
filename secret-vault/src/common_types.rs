use chrono::prelude::*;
use rsb_derive::*;
use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretName(String);

impl AsRef<[u8]> for &SecretName {
    fn as_ref(&self) -> &[u8] {
        self.value().as_bytes()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretNamespace(String);

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretVersion(String);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SecretVaultRef {
    pub key: SecretVaultKey,

    pub required: bool,
    pub auto_refresh: bool,
    pub allow_in_snapshots: bool,
}

impl SecretVaultRef {
    pub fn new(secret_name: SecretName) -> Self {
        Self {
            key: SecretVaultKey::new(secret_name),
            required: true,
            auto_refresh: false,
            allow_in_snapshots: false,
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

    pub fn with_required(self, value: bool) -> Self {
        Self {
            required: value,
            ..self
        }
    }

    pub fn with_auto_refresh(self, value: bool) -> Self {
        Self {
            auto_refresh: value,
            ..self
        }
    }

    pub fn with_allow_in_snapshots(self, value: bool) -> Self {
        Self {
            allow_in_snapshots: value,
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretMetadataLabel {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct SecretMetadata {
    #[default = "Utc::now()"]
    pub cached_at: DateTime<Utc>,
    pub key: SecretVaultKey,
    pub labels: Option<Vec<SecretMetadataLabel>>,
    pub description: Option<String>,
    pub expire_at: Option<DateTime<Utc>>,
    pub version: Option<SecretVersion>,
}

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct Secret {
    pub value: SecretValue,
    pub metadata: SecretMetadata,
}

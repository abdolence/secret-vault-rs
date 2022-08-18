use crate::vault_store::SecretVaultKey;
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretVaultRef {
    pub secret_name: SecretName,
    pub secret_version: Option<SecretVersion>,
    pub namespace: Option<SecretNamespace>,

    #[default = "true"]
    pub required: bool,

    #[default = "false"]
    pub auto_refresh: bool,

    #[default = "false"]
    pub allow_in_snapshots: bool,
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

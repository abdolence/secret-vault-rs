use chrono::prelude::*;
use rsb_derive::*;
use rvstruct::*;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretName(String);

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
    pub predefined_labels: Vec<SecretMetadataLabel>,
}

impl SecretVaultRef {
    pub fn new(secret_name: SecretName) -> Self {
        Self {
            key: SecretVaultKey::new(secret_name),
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
    #[default = "Utc::now()"]
    pub cached_at: DateTime<Utc>,
    pub key: SecretVaultKey,
    pub labels: Option<Vec<SecretMetadataLabel>>,
    pub annotations: Option<Vec<SecretMetadataAnnotation>>,
    pub description: Option<String>,
    pub expiration: Option<SecretExpiration>,
    pub version: Option<SecretVersion>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
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
    ExpireTime(chrono::DateTime<chrono::Utc>),
    Ttl(chrono::Duration),
}

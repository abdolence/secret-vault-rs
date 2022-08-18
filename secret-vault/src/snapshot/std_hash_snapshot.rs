use crate::vault_store::SecretVaultKey;
use crate::*;
use std::collections::HashMap;

pub struct SecretVaultHashMapSnapshot {
    secrets_map: HashMap<SecretVaultKey, Secret>,
}

impl SecretVaultHashMapSnapshot {
    pub fn with_secrets(secrets: Vec<Secret>) -> Self {
        let secrets_map: HashMap<SecretVaultKey, Secret> = secrets
            .into_iter()
            .map(|secret| (secret.metadata.key.clone(), secret))
            .collect();

        Self { secrets_map }
    }
}

pub struct SecretVaultHashMapSnapshotBuilder;

impl SecretVaultHashMapSnapshotBuilder {
    pub fn new() -> Self {
        Self {}
    }
}

impl SecretVaultSnapshotBuilder<SecretVaultHashMapSnapshot> for SecretVaultHashMapSnapshotBuilder {
    fn build_snapshot(&self, secrets: Vec<Secret>) -> SecretVaultHashMapSnapshot {
        SecretVaultHashMapSnapshot::with_secrets(secrets)
    }
}

impl SecretVaultSnapshot for SecretVaultHashMapSnapshot {
    fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>> {
        Ok(self.secrets_map.get(&secret_ref.clone().into()).cloned())
    }
}

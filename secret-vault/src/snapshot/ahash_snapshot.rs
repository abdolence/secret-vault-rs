use crate::vault_store::SecretVaultKey;
use crate::*;
use ahash::AHashMap;

pub struct SecretVaultAhashSnapshot {
    secrets_map: AHashMap<SecretVaultKey, Secret>,
}

impl SecretVaultAhashSnapshot {
    pub fn with_secrets(secrets: Vec<Secret>) -> Self {
        let secrets_map: AHashMap<SecretVaultKey, Secret> = secrets
            .into_iter()
            .map(|secret| (secret.metadata.key.clone(), secret))
            .collect();

        Self { secrets_map }
    }
}

pub struct SecretVaultAhashSnapshotBuilder;

impl SecretVaultAhashSnapshotBuilder {
    pub fn new() -> Self {
        Self {}
    }
}

impl SecretVaultSnapshotBuilder<SecretVaultAhashSnapshot> for SecretVaultAhashSnapshotBuilder {
    fn build_snapshot(&self, secrets: Vec<Secret>) -> SecretVaultAhashSnapshot {
        SecretVaultAhashSnapshot::with_secrets(secrets)
    }
}

impl SecretVaultSnapshot for SecretVaultAhashSnapshot {
    fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>> {
        Ok(self.secrets_map.get(&secret_ref.clone().into()).cloned())
    }
}

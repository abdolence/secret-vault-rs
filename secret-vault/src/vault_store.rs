use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common_types::*;
use crate::encryption::*;
use crate::SecretVaultResult;

#[cfg(not(feature = "ahash"))]
type SecretVaultMap = std::collections::HashMap<SecretVaultKey, SecretVaultStoreValue>;

#[cfg(feature = "ahash")]
type SecretVaultMap = ahash::AHashMap<SecretVaultKey, SecretVaultStoreValue>;

#[derive(Debug)]
pub struct SecretVaultStoreValue {
    pub data: EncryptedSecretValue,
    pub metadata: SecretMetadata,
}

#[derive(Debug)]
pub struct SecretVaultStore<E>
where
    E: SecretVaultEncryption,
{
    secrets: Arc<RwLock<SecretVaultMap>>,
    encrypter: E,
}

impl<E> SecretVaultStore<E>
where
    E: SecretVaultEncryption,
{
    pub fn new(encrypter: E) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(SecretVaultMap::new())),
            encrypter,
        }
    }

    pub async fn insert(
        &self,
        secret_ref: SecretVaultRef,
        secret: &Secret,
    ) -> SecretVaultResult<()> {
        let encrypted_secret_value = self
            .encrypter
            .encrypt_value(&secret_ref.key, &secret.value)
            .await?;

        let mut secrets_write = self.secrets.write().await;
        secrets_write.insert(
            secret_ref.key,
            SecretVaultStoreValue {
                data: encrypted_secret_value,
                metadata: secret.metadata.clone(),
            },
        );

        Ok(())
    }

    pub async fn get_secret(
        &self,
        secret_vault_key: &SecretVaultKey,
    ) -> SecretVaultResult<Option<Secret>> {
        let secrets_read = self.secrets.read().await;

        match secrets_read.get(secret_vault_key) {
            Some(stored_value) => {
                let secret_value = self
                    .encrypter
                    .decrypt_value(secret_vault_key, &stored_value.data)
                    .await?;
                Ok(Some(Secret::new(
                    secret_value,
                    stored_value.metadata.clone(),
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn remove(&self, secret_vault_key: &SecretVaultKey) -> SecretVaultResult<()> {
        let mut secrets_write = self.secrets.write().await;
        secrets_write.remove(secret_vault_key);
        Ok(())
    }

    pub async fn contains(&self, secret_refs: &[SecretVaultRef]) -> bool {
        let secrets_read = self.secrets.read().await;
        secret_refs
            .iter()
            .all(|secret_ref| secrets_read.contains_key(&secret_ref.key))
    }

    pub async fn compact(&self, secret_refs: &[SecretVaultRef]) -> SecretVaultResult<()> {
        let mut secrets_write = self.secrets.write().await;
        let to_remove: Vec<SecretVaultKey> = secrets_write
            .keys()
            .filter(|key| !secret_refs.iter().any(|secret_ref| secret_ref.key == **key))
            .cloned()
            .collect();

        for key in to_remove {
            secrets_write.remove(&key);
        }

        Ok(())
    }

    pub async fn exists<'a>(
        &'a self,
        secret_refs: &'a Vec<SecretVaultRef>,
    ) -> (Vec<&'a SecretVaultRef>, Vec<&'a SecretVaultRef>) {
        let secrets_read = self.secrets.read().await;
        let mut missing = Vec::new();
        let mut existing = Vec::new();
        for secret_ref in secret_refs {
            if secrets_read.contains_key(&secret_ref.key) {
                existing.push(secret_ref);
            } else {
                missing.push(secret_ref);
            }
        }
        (existing, missing)
    }

    pub async fn len(&self) -> usize {
        let secrets_read = self.secrets.read().await;
        secrets_read.len()
    }
}

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common_types::*;
use crate::encryption::*;
use crate::SecretVaultResult;

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
    secrets: Arc<RwLock<HashMap<SecretVaultKey, SecretVaultStoreValue>>>,
    encrypter: E,
}

impl<E> SecretVaultStore<E>
where
    E: SecretVaultEncryption,
{
    pub fn new(encrypter: E) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
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
        secret_ref: &SecretVaultRef,
    ) -> SecretVaultResult<Option<Secret>> {
        let secrets_read = self.secrets.read().await;

        match secrets_read.get(&secret_ref.key) {
            Some(stored_value) => {
                let secret_value = self
                    .encrypter
                    .decrypt_value(&secret_ref.key, &stored_value.data)
                    .await?;
                Ok(Some(Secret::new(
                    secret_value,
                    stored_value.metadata.clone(),
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn len(&self) -> usize {
        let secrets_read = self.secrets.read().await;
        secrets_read.len()
    }
}

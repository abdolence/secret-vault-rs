use crate::encryption::EncryptedSecretValue;
use crate::{SecretMetadata, SecretVaultResult};

#[derive(Debug)]
pub struct SecretVaultStoreValue<R> {
    pub data: R,
    pub metadata: SecretMetadata,
}

pub trait SecretVaultStoreValueAllocator {
    type R;

    fn allocate(&mut self, encrypted_secret: EncryptedSecretValue) -> SecretVaultResult<Self::R>;

    fn extract(&self, allocated: &Self::R) -> SecretVaultResult<EncryptedSecretValue>;
    fn destroy(&mut self, value: Self::R);
}

#[derive(Debug)]
pub struct SecretVaultNoAllocator;

impl SecretVaultStoreValueAllocator for SecretVaultNoAllocator {
    type R = EncryptedSecretValue;

    fn allocate(&mut self, encrypted_secret: EncryptedSecretValue) -> SecretVaultResult<Self::R> {
        Ok(encrypted_secret)
    }

    fn extract(&self, allocated: &Self::R) -> SecretVaultResult<EncryptedSecretValue> {
        Ok(allocated.clone())
    }

    fn destroy(&mut self, value: Self::R) {
        drop(value)
    }
}

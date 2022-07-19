use crate::encryption::EncryptedSecretValue;
use crate::SecretVaultResult;

pub struct SecretVaultStoreValue<R> {
    pub data: R,
}

pub trait SecretVaultStoreValueAllocator {
    type R;

    fn allocate(
        &mut self,
        encrypted_secret: EncryptedSecretValue,
    ) -> SecretVaultResult<SecretVaultStoreValue<Self::R>>;

    fn extract(
        &self,
        allocated: &SecretVaultStoreValue<Self::R>,
    ) -> SecretVaultResult<EncryptedSecretValue>;
    fn destroy(&mut self, value: SecretVaultStoreValue<Self::R>);
}

pub struct SecretVaultStoreValueNoAllocator;

impl SecretVaultStoreValueAllocator for SecretVaultStoreValueNoAllocator {
    type R = EncryptedSecretValue;

    fn allocate(
        &mut self,
        encrypted_secret: EncryptedSecretValue,
    ) -> SecretVaultResult<SecretVaultStoreValue<Self::R>> {
        Ok(SecretVaultStoreValue {
            data: encrypted_secret,
        })
    }

    fn extract(
        &self,
        allocated: &SecretVaultStoreValue<Self::R>,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        Ok(allocated.data.clone().into())
    }

    fn destroy(&mut self, value: SecretVaultStoreValue<Self::R>) {
        drop(value)
    }
}

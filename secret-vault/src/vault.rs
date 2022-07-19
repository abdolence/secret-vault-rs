use crate::allocator::SecretVaultStoreValueAllocator;
use crate::encryption::SecretVaultEncryption;
use crate::secrets_source::SecretsSource;
use crate::SecretVaultResult;
use crate::vault_store::SecretVaultStore;

pub struct SecretVault<S, R, AR, E> where
    S: SecretsSource,
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator<R = R> {

    source: S,
    store: SecretVaultStore<R,AR,E>,

}

impl<S, R, AR, E> SecretVault<S, R, AR, E> where
    S: SecretsSource,
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator<R = R>{

    pub fn new ( source: S, store: SecretVaultStore<R,AR,E> ) -> SecretVaultResult<Self>{
        Ok(
            Self {
                source,
                store
            }
        )
    }
}

use crate::encryption::*;
use crate::vault_store::SecretVaultStore;
use crate::*;

pub struct SecretVaultBuilder;

impl SecretVaultBuilder {
    pub fn with_source<S: SecretsSource>(source: S) -> SecretVaultBuilderWithSource<S> {
        SecretVaultBuilderWithSource(source)
    }
}

pub struct SecretVaultBuilderWithSource<S: SecretsSource>(S);

impl<S: SecretsSource> SecretVaultBuilderWithSource<S> {
    pub fn with_encryption<E: SecretVaultEncryption>(
        self,
        encryption: E,
    ) -> SecretVaultBuilderWithEncryption<S, E> {
        SecretVaultBuilderWithEncryption {
            source: self.0,
            encryption,
        }
    }

    pub fn without_encryption(self) -> SecretVaultBuilderWithEncryption<S, NoEncryption> {
        SecretVaultBuilderWithEncryption {
            source: self.0,
            encryption: NoEncryption {},
        }
    }
}

pub struct SecretVaultBuilderWithEncryption<S: SecretsSource, E: SecretVaultEncryption> {
    source: S,
    encryption: E,
}

impl<S: SecretsSource, E: SecretVaultEncryption> SecretVaultBuilderWithEncryption<S, E> {
    pub fn with_memory_protection<AR: SecretVaultStoreValueAllocator>(
        self,
        allocator: AR,
    ) -> SecretVaultBuilderWithAllocator<S, E, AR> {
        SecretVaultBuilderWithAllocator {
            source: self.source,
            encryption: self.encryption,
            allocator,
        }
    }

    pub fn without_memory_protection(
        self,
    ) -> SecretVaultBuilderWithAllocator<S, E, SecretVaultStoreValueNoAllocator> {
        SecretVaultBuilderWithAllocator {
            source: self.source,
            encryption: self.encryption,
            allocator: SecretVaultStoreValueNoAllocator,
        }
    }
}

pub struct SecretVaultBuilderWithAllocator<
    S: SecretsSource,
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
> {
    source: S,
    encryption: E,
    allocator: AR,
}

impl<S: SecretsSource, E: SecretVaultEncryption, AR: SecretVaultStoreValueAllocator>
    SecretVaultBuilderWithAllocator<S, E, AR>
{
    pub fn build(self) -> SecretVaultResult<SecretVault<S, AR::R, AR, E>> {
        let store = SecretVaultStore::new(self.encryption, self.allocator);
        SecretVault::new(self.source, store)
    }
}

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

    pub fn without_encryption(
        self,
    ) -> SecretVaultBuilderWithEncryption<S, SecretVaultNoEncryption> {
        SecretVaultBuilderWithEncryption {
            source: self.0,
            encryption: SecretVaultNoEncryption {},
        }
    }
}

pub struct SecretVaultBuilderWithEncryption<S: SecretsSource, E: SecretVaultEncryption> {
    source: S,
    encryption: E,
}

impl<S: SecretsSource, E: SecretVaultEncryption> SecretVaultBuilderWithEncryption<S, E> {
    pub fn build(self) -> SecretVaultResult<SecretVault<S, E>> {
        let store = SecretVaultStore::new(self.encryption);
        SecretVault::new(self.source, store)
    }
}

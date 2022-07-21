use crate::*;

pub struct SecretVaultBuilder<
    S: SecretsSource + Sync + Send,
    E: SecretVaultEncryption + Sync + Send = SecretVaultNoEncryption,
> {
    source: S,
    encryption: E,
}

impl<S> SecretVaultBuilder<S, SecretVaultNoEncryption>
    where
        S: SecretsSource + Sync + Send
{
    pub fn with_source(source: S) -> SecretVaultBuilder<S, SecretVaultNoEncryption> {
        SecretVaultBuilder { source, encryption: SecretVaultNoEncryption {} }
    }
}

impl<S, E> SecretVaultBuilder<S, E>
where
    S: SecretsSource + Sync + Send,
    E: SecretVaultEncryption + Sync + Send,
{
    pub fn with_encryption<NE>(
        self,
        encryption: NE,
    ) -> SecretVaultBuilder<S, NE>
        where
            NE: SecretVaultEncryption + Sync + Send
    {
        SecretVaultBuilder {
            source: self.source,
            encryption,
        }
    }

    pub fn without_encryption(
        self
    ) -> SecretVaultBuilder<S, SecretVaultNoEncryption>
        where
            E: Sync + Send,
    {
        SecretVaultBuilder {
            source: self.source,
            encryption: SecretVaultNoEncryption {}
        }
    }

    pub fn build(self) -> SecretVaultResult<SecretVault<S, E>> {
        SecretVault::new(self.source, self.encryption)
    }
}

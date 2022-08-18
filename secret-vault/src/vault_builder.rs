use crate::*;

pub struct SecretVaultBuilder<
    S: SecretsSource + Sync + Send,
    E: SecretVaultEncryption + Sync + Send = SecretVaultNoEncryption,
> {
    source: S,
    encryption: E,
    refs: Vec<SecretVaultRef>,
}

impl<S> SecretVaultBuilder<S, SecretVaultNoEncryption>
where
    S: SecretsSource + Sync + Send,
{
    pub fn with_source(source: S) -> SecretVaultBuilder<S, SecretVaultNoEncryption> {
        SecretVaultBuilder {
            source,
            encryption: SecretVaultNoEncryption {},
            refs: Vec::new(),
        }
    }
}

impl<S, E> SecretVaultBuilder<S, E>
where
    S: SecretsSource + Sync + Send,
    E: SecretVaultEncryption + Sync + Send,
{
    pub fn with_encryption<NE>(self, encryption: NE) -> SecretVaultBuilder<S, NE>
    where
        NE: SecretVaultEncryption + Sync + Send,
    {
        SecretVaultBuilder {
            source: self.source,
            encryption,
            refs: Vec::new(),
        }
    }

    pub fn without_encryption(self) -> SecretVaultBuilder<S, SecretVaultNoEncryption>
    where
        E: Sync + Send,
    {
        SecretVaultBuilder {
            source: self.source,
            encryption: SecretVaultNoEncryption {},
            refs: Vec::new(),
        }
    }

    pub fn with_secret_refs(self, secret_refs: Vec<&SecretVaultRef>) -> SecretVaultBuilder<S, E> {
        SecretVaultBuilder {
            source: self.source,
            encryption: self.encryption,
            refs: secret_refs.into_iter().cloned().collect(),
        }
    }

    pub fn build(self) -> SecretVaultResult<SecretVault<S, E>> {
        let vault = SecretVault::new(self.source, self.encryption)?;

        Ok(if !self.refs.is_empty() {
            vault.with_secret_refs(self.refs.iter().collect())
        } else {
            vault
        })
    }
}

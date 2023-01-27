use crate::errors::*;
use crate::*;

pub trait SecretVaultSnapshot {
    fn get_secret(&self, secret_name: &SecretName) -> SecretVaultResult<Option<Secret>> {
        self.get_secret_with_version(secret_name, None)
    }

    fn require_secret(&self, secret_name: &SecretName) -> SecretVaultResult<Secret> {
        self.require_secret_with_version(secret_name, None)
    }

    fn get_secret_with_version(
        &self,
        secret_name: &SecretName,
        secret_version: Option<&SecretVersion>,
    ) -> SecretVaultResult<Option<Secret>> {
        self.get_secret_by_ref(
            &SecretVaultRef::new(secret_name.clone()).opt_secret_version(secret_version.cloned()),
        )
    }

    fn require_secret_with_version(
        &self,
        secret_name: &SecretName,
        secret_version: Option<&SecretVersion>,
    ) -> SecretVaultResult<Secret> {
        self.require_secret_by_ref(
            &SecretVaultRef::new(secret_name.clone()).opt_secret_version(secret_version.cloned()),
        )
    }

    fn require_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Secret> {
        match self.get_secret_by_ref(secret_ref)? {
            Some(secret) => Ok(secret),
            None => Err(SecretVaultError::DataNotFoundError(
                SecretVaultDataNotFoundError::new(
                    SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                    format!("Secret {secret_ref:?} doesn't exist in vault but was required"),
                ),
            )),
        }
    }

    fn get_secret_by_ref(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>>;
}

pub trait SecretVaultSnapshotBuilder<SN>
where
    SN: SecretVaultSnapshot,
{
    fn build_snapshot(&self, secrets: Vec<Secret>) -> SN;
}

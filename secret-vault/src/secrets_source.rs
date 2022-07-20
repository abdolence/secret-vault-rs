use crate::{Secret, SecretVaultRef, SecretVaultResult};
use async_trait::*;
use std::collections::HashMap;

#[async_trait]
pub trait SecretsSource {
    fn name(&self) -> String;

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>>;
}

use crate::{SecretVaultRef, SecretVaultResult};
use async_trait::*;
use secret_vault_value::SecretValue;
use std::collections::HashMap;

#[async_trait]
pub trait SecretsSource {
    fn name(&self) -> String;

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, SecretValue>>;
}

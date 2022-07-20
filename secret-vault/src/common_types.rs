use rvstruct::*;
use rsb_derive::*;

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretName(String);

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretVersion(String);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretVaultRef {
    pub secret_name: SecretName,
    pub secret_version: Option<SecretVersion>,
}

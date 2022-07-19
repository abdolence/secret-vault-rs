use rvstruct::*;

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretName(String);

#[derive(Debug, Clone, Eq, PartialEq, Hash, ValueStruct)]
pub struct SecretVersion(String);

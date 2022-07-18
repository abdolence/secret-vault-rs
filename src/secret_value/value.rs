use zeroize::*;

#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(src: Vec<u8>) -> Self {
        Self(src)
    }
    pub fn ref_sensitive_value(&self) -> &Vec<u8> {
        &self.0
    }
}

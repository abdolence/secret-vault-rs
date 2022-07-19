use std::fmt::{Debug, Display, Formatter};
use zeroize::*;

#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Default)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(src: Vec<u8>) -> Self {
        Self(src)
    }

    pub fn ref_sensitive_value(&self) -> &Vec<u8> {
        &self.0
    }

    pub fn ref_sensitive_value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        SecretValue::new(self.ref_sensitive_value().clone())
    }
}

impl Display for SecretValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

impl Debug for SecretValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    fn generate_secret_value() -> BoxedStrategy<SecretValue> {
        ("[a-zA-Z0-9]*")
            .prop_map(|(mock_secret_str)| SecretValue::new(mock_secret_str.as_bytes().to_vec()))
            .boxed()
    }

    proptest! {
        #[test]
        fn secret_is_not_leaking_in_fmt(mock_secret_value in generate_secret_value()) {
            assert_eq!(format!("{}",mock_secret_value), "***");
            assert_eq!(format!("{:?}",mock_secret_value), "***");
            assert_eq!(format!("{:#?}",mock_secret_value), "***");
        }

        #[test]
        fn secret_follows_partial_eq(mock_secret_str in "[a-zA-Z0-9]*") {
            let mock_secret1 = SecretValue::new(mock_secret_str.as_bytes().to_vec());
            let mock_secret2 = SecretValue::new(mock_secret_str.as_bytes().to_vec());
            assert_eq!(mock_secret1, mock_secret2);
        }
    }
}

use crate::SecretValue;
use base64::prelude::*;
use zeroize::{Zeroize, Zeroizing};

impl SecretValue {
    pub fn as_sensitive_base64_str(&self) -> Zeroizing<String> {
        BASE64_STANDARD.encode(self.as_sensitive_bytes()).into()
    }

    pub fn to_base64_str(&self) -> Self {
        Self::from(&self.as_sensitive_base64_str())
    }

    pub fn from_base64_str(mut base64_string: String) -> Result<Self, base64::DecodeError> {
        let result = Self::new(BASE64_STANDARD.decode(&base64_string)?);
        base64_string.zeroize();
        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    fn generate_secret_value() -> BoxedStrategy<SecretValue> {
        ".*".prop_map(|(mock_bytes)| SecretValue::new(mock_bytes.into()))
            .boxed()
    }

    proptest! {
        #[test]
        fn test_base64_encode(secret_value in generate_secret_value()) {
            let base64_str = secret_value.as_sensitive_base64_str();
            assert_eq!(secret_value.as_sensitive_bytes(), BASE64_STANDARD.decode(base64_str).unwrap());

            let base64_value = secret_value.to_base64_str();
            assert_eq!(secret_value.as_sensitive_bytes(), BASE64_STANDARD.decode(base64_value.as_sensitive_str()).unwrap());
        }

        #[test]
        fn test_base64_decode(mock_str in ".*") {
            let base64_str = BASE64_STANDARD.encode(mock_str.as_bytes());
            let secret_value = SecretValue::from_base64_str(base64_str).unwrap();
            assert_eq!(secret_value.as_sensitive_bytes(), mock_str.as_bytes());
        }
    }
}

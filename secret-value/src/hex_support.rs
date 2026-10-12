use crate::SecretValue;
use zeroize::{Zeroize, Zeroizing};

impl SecretValue {
    /// Encodes the secret as a lowercase hex string that is zeroized on drop.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::new(vec![0xca, 0xfe]);
    /// assert_eq!(secret_value.as_sensitive_hex_str().as_str(), "cafe");
    /// ```
    pub fn as_sensitive_hex_str(&self) -> Zeroizing<String> {
        hex::encode(self.as_sensitive_bytes()).into()
    }

    /// Returns a new secret holding the hex text of this one.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::new(vec![0xca, 0xfe]);
    /// assert_eq!(secret_value.to_hex_str().as_sensitive_str(), "cafe");
    /// ```
    pub fn to_hex_str(&self) -> Self {
        Self::from(&self.as_sensitive_hex_str())
    }

    /// Decodes a hex string, upper or lower case, into a secret.
    ///
    /// The input string is zeroized after a successful decode.
    ///
    /// # Errors
    ///
    /// Returns [`hex::FromHexError`] if the input is not valid hex.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::from_hex_str("cafe".to_string())?;
    /// assert_eq!(secret_value.as_sensitive_bytes(), [0xca, 0xfe]);
    /// # Ok::<(), hex::FromHexError>(())
    /// ```
    pub fn from_hex_str(mut hex_string: String) -> Result<Self, hex::FromHexError> {
        let result = Self::new(hex::decode(&hex_string)?);
        hex_string.zeroize();
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
        fn test_hex_encode(secret_value in generate_secret_value()) {
            let hex_str = secret_value.as_sensitive_hex_str();
            assert_eq!(secret_value.as_sensitive_bytes(), hex::decode(hex_str).unwrap());

            let hex_value = secret_value.to_hex_str();
            assert_eq!(secret_value.as_sensitive_bytes(), hex::decode(hex_value.as_sensitive_str()).unwrap());
        }

        #[test]
        fn test_hex_decode(mock_str in ".*") {
            let hex_str = hex::encode(mock_str.as_bytes());
            let secret_value = SecretValue::from_hex_str(hex_str).unwrap();
            assert_eq!(secret_value.as_sensitive_bytes(), mock_str.as_bytes());
        }
    }
}

use crate::SecretValue;
use base64::prelude::*;
use zeroize::Zeroizing;

impl SecretValue {
    /// Encodes the secret as standard padded base64 in a string that is
    /// zeroized on drop.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::from("my-password");
    /// assert_eq!(secret_value.as_sensitive_base64_str().as_str(), "bXktcGFzc3dvcmQ=");
    /// ```
    pub fn as_sensitive_base64_str(&self) -> Zeroizing<String> {
        BASE64_STANDARD.encode(self.as_sensitive_bytes()).into()
    }

    /// Returns a new secret holding the standard padded base64 text of this
    /// one.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::from("my-password");
    /// assert_eq!(secret_value.to_base64_str().as_sensitive_str(), "bXktcGFzc3dvcmQ=");
    /// ```
    pub fn to_base64_str(&self) -> Self {
        Self::from(&self.as_sensitive_base64_str())
    }

    /// Decodes standard padded base64 into a secret.
    ///
    /// The input string is zeroized whether the decode succeeds or not.
    ///
    /// # Errors
    ///
    /// Returns [`base64::DecodeError`] if the input is not valid standard
    /// base64.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::from_base64_str("bXktcGFzc3dvcmQ=".to_string())?;
    /// assert_eq!(secret_value.as_sensitive_str(), "my-password");
    /// # Ok::<(), base64::DecodeError>(())
    /// ```
    pub fn from_base64_str(base64_string: String) -> Result<Self, base64::DecodeError> {
        let base64_string = Zeroizing::new(base64_string);
        Ok(Self::new(BASE64_STANDARD.decode(base64_string.as_str())?))
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

use crate::*;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

impl SecretValue {
    /// Parses the secret as JSON into `T`.
    ///
    /// The `Zeroize` bound lets the caller wipe the result, but the result is
    /// not zeroised automatically: call `zeroize()` on it, or wrap it in
    /// [`zeroize::Zeroizing`], once it is no longer needed.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if the secret is not valid JSON for `T`.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    /// use serde::Deserialize;
    /// use zeroize::{Zeroize, Zeroizing};
    ///
    /// #[derive(Deserialize, Zeroize)]
    /// struct Credentials {
    ///     user: String,
    ///     password: String,
    /// }
    ///
    /// let secret_value = SecretValue::from(r#"{"user":"admin","password":"my-password"}"#);
    /// let credentials = Zeroizing::new(secret_value.expose_json_value_as::<Credentials>()?);
    /// assert_eq!(credentials.user, "admin");
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    pub fn expose_json_value_as<T>(&self) -> serde_json::Result<T>
    where
        for<'de> T: Deserialize<'de> + Zeroize,
    {
        serde_json::from_slice(self.ref_sensitive_value())
    }
}

/// Serialises the secret as a string.
///
/// Fails if the bytes are not valid UTF-8.
impl Serialize for SecretValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            String::from_utf8(self.ref_sensitive_value().clone())
                .map_err(serde::ser::Error::custom)?
                .as_str(),
        )
    }
}

struct SecretValueVisitor;

#[allow(clippy::needless_lifetimes)]
impl<'de> Visitor<'de> for SecretValueVisitor {
    type Value = SecretValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string expected as a secret value")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SecretValue::new(value.as_bytes().to_vec()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SecretValue::new(value.into_bytes()))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SecretValue::new(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SecretValue::new(value))
    }
}

/// Deserialises the secret from a string or from bytes.
impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<SecretValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(SecretValueVisitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn serialize_as_string(mock_secret in "[a-zA-Z0-9]*") {
            let mock_secret_vec = mock_secret.as_bytes().to_vec();
            let secret_value = SecretValue::new(mock_secret_vec);
            let test_serialized_string = serde_json::to_string(&secret_value).unwrap();
            assert_eq!(test_serialized_string, format!("\"{}\"",mock_secret));
        }

        #[test]
        fn deserialize_from_string(mock_secret in "[a-zA-Z0-9]*") {
            let mock_secret_quoted = format!("\"{}\"",mock_secret);
            let secret_value: SecretValue = serde_json::from_str(&mock_secret_quoted).unwrap();
            assert_eq!(String::from_utf8(secret_value.ref_sensitive_value().clone()).unwrap(), mock_secret);
        }
    }

    #[test]
    fn deserialize_embedded_json() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
        struct TestJson {
            pub test_field: String,
        }
        let mock_json_struct = TestJson {
            test_field: "TestValue".into(),
        };

        let secret_value: SecretValue = serde_json::to_string(&mock_json_struct).unwrap().into();

        assert_eq!(
            secret_value.expose_json_value_as::<TestJson>().unwrap(),
            mock_json_struct
        );
    }
}

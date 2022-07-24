use crate::*;
use zeroize::*;

use bytes::BytesMut;

impl From<BytesMut> for SecretValue {
    fn from(mut bytes: BytesMut) -> SecretValue {
        let result = SecretValue::new(bytes.to_vec());
        bytes.zeroize();
        bytes.truncate(0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
         #[test]
         fn serialize_as_string(mock_secret in "[a-zA-Z0-9]*") {
             let mock_secret_bytes = bytes::BytesMut::from(mock_secret.as_str());
             let secret_value = SecretValue::from(mock_secret_bytes);

             assert_eq!(mock_secret.as_str(), secret_value.sensitive_value_to_str().unwrap())
         }
    }
}

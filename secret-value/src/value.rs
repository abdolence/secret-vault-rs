use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::str::Utf8Error;
use zeroize::*;

#[derive(Zeroize, ZeroizeOnDrop, Eq, PartialEq, Default)]
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

    pub fn sensitive_value_to_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    pub fn secure_clear(&mut self) {
        self.0.zeroize();
        self.0.clear();
    }

    pub fn exposed_in_as_str<T, Z: Zeroize>(&self, f: fn(String) -> (T,Z)) -> T {
        let decoded_as_string = String::from_utf8(self.0.clone()).unwrap();
        let (result, mut zeroizable) = f(decoded_as_string);
        zeroizable.zeroize();
        result
    }

    pub fn exposed_in_as_vec<T, Z: Zeroize>(&self, f: fn(Vec<u8>) -> (T,Z)) -> T {
        let (result, mut zeroizable) = f(self.0.clone());
        zeroizable.zeroize();
        result
    }

    pub async fn exposed_in_as_str_async<T, Z: Zeroize, FI>(&self, f: fn(String) -> FI) -> T where FI: Future<Output=(T,Z)> {
        let decoded_as_string = String::from_utf8(self.0.clone()).unwrap();
        let (result, mut zeroizable) = f(decoded_as_string).await;
        zeroizable.zeroize();
        result
    }

    pub async fn exposed_in_as_vec_async<T, Z: Zeroize, FI>(&self, f: fn(Vec<u8>) -> FI) -> T where FI: Future<Output=(T,Z)> {
        let (result, mut zeroizable) = f(self.0.clone()).await;
        zeroizable.zeroize();
        result
    }
}

impl From<String> for SecretValue {
    fn from(mut str: String) -> Self {
        let result = Self(str.as_bytes().to_vec());
        str.zeroize();
        result
    }
}

impl From<&mut String> for SecretValue {
    fn from(str: &mut String) -> Self {
        let result = Self(str.as_bytes().to_vec());
        str.zeroize();
        result
    }
}

impl From<Vec<u8>> for SecretValue {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<&mut Vec<u8>> for SecretValue {
    fn from(vec: &mut Vec<u8>) -> Self {
        let result = Self(vec.clone());
        vec.zeroize();
        vec.clear();
        result
    }
}

impl From<&str> for SecretValue {
    fn from(str: &str) -> Self {
        Self(str.as_bytes().to_vec())
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
    use proptest::test_runner::TestRunner;

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

        #[test]
        fn exposed_function_str(mock_secret_value in generate_secret_value())  {
            let insecure_copy_str =
            mock_secret_value.exposed_in_as_str(|str| {
                (str.clone(), str)
            });
            assert_eq!(insecure_copy_str.as_str(), mock_secret_value.sensitive_value_to_str().unwrap());
        }

        #[test]
        fn exposed_function_vec(mock_secret_value in generate_secret_value())  {
            let insecure_copy_vec =
                mock_secret_value.exposed_in_as_vec(|vec| {
                    (vec.clone(), vec)
                });
            assert_eq!(&insecure_copy_vec, mock_secret_value.ref_sensitive_value());
        }
    }

    #[tokio::test]
    async fn exposed_function_str_async() {
        let mut runner = TestRunner::default();
        let mock_secret = generate_secret_value()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let insecure_copy_str =
            mock_secret.exposed_in_as_str_async(|str| async {
                (str.clone(), str)
            }).await;
        assert_eq!(insecure_copy_str.as_str(), mock_secret.sensitive_value_to_str().unwrap());
    }

    #[tokio::test]
    async fn exposed_function_vec_async() {
        let mut runner = TestRunner::default();
        let mock_secret = generate_secret_value()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let insecure_copy_vec =
            mock_secret.exposed_in_as_vec_async(|vec| async {
                (vec.clone(), vec)
            }).await;
        assert_eq!(&insecure_copy_vec, mock_secret.ref_sensitive_value());
    }

}

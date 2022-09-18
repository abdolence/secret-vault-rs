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

    pub fn as_sensitive_str(&self) -> &str {
        self.sensitive_value_to_str().unwrap()
    }

    pub fn as_sensitive_bytes(&self) -> &[u8] {
        self.ref_sensitive_value()
    }

    pub fn exposed_in_as_str<T, Z: Zeroize, FN>(&self, f: FN) -> T
    where
        FN: Fn(String) -> (T, Z),
    {
        let decoded_as_string = self.sensitive_value_to_str().unwrap().to_string();
        let (result, mut zeroizable) = f(decoded_as_string);
        zeroizable.zeroize();
        result
    }

    pub fn exposed_in_as_zstr<T, FN>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<String>) -> T,
    {
        let decoded_as_string = Zeroizing::new(self.sensitive_value_to_str().unwrap().to_string());
        f(decoded_as_string)
    }

    pub fn exposed_in_as_vec<T, Z: Zeroize, FN>(&self, f: FN) -> T
    where
        FN: Fn(Vec<u8>) -> (T, Z),
    {
        let (result, mut zeroizable) = f(self.0.clone());
        zeroizable.zeroize();
        result
    }

    pub fn exposed_in_as_zvec<T, FN>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<Vec<u8>>) -> T,
    {
        f(Zeroizing::new(self.0.clone()))
    }

    pub async fn exposed_in_as_str_async<T, Z: Zeroize, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(String) -> FI,
        FI: Future<Output = (T, Z)>,
    {
        let decoded_as_string = self.sensitive_value_to_str().unwrap().to_string();
        let (result, mut zeroizable) = f(decoded_as_string).await;
        zeroizable.zeroize();
        result
    }

    pub async fn exposed_in_as_zstr_async<T, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<String>) -> FI,
        FI: Future<Output = T>,
    {
        let decoded_as_string = Zeroizing::new(self.sensitive_value_to_str().unwrap().to_string());
        f(decoded_as_string).await
    }

    pub async fn exposed_in_as_vec_async<T, Z: Zeroize, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(Vec<u8>) -> FI,
        FI: Future<Output = (T, Z)>,
    {
        let (result, mut zeroizable) = f(self.0.clone()).await;
        zeroizable.zeroize();
        result
    }

    pub async fn exposed_in_as_zvec_async<T, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<Vec<u8>>) -> FI,
        FI: Future<Output = T>,
    {
        f(Zeroizing::new(self.0.clone())).await
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

impl From<&Zeroizing<String>> for SecretValue {
    fn from(str: &Zeroizing<String>) -> Self {
        Self(str.as_bytes().to_vec())
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

impl From<&Zeroizing<Vec<u8>>> for SecretValue {
    fn from(vec: &Zeroizing<Vec<u8>>) -> Self {
        Self(vec.to_vec())
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
    use std::ops::Deref;

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
        fn exposed_function_zstr(mock_secret_value in generate_secret_value())  {
            let insecure_copy_str =
            mock_secret_value.exposed_in_as_zstr(|str| {
                str.clone()
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


        #[test]
        fn exposed_function_zvec(mock_secret_value in generate_secret_value())  {
            let insecure_copy_vec =
                mock_secret_value.exposed_in_as_zvec(|vec| {
                    vec.clone()
                });
            assert_eq!(insecure_copy_vec.deref(), mock_secret_value.ref_sensitive_value());
        }
    }

    #[tokio::test]
    async fn exposed_function_str_async() {
        let mut runner = TestRunner::default();
        let mock_secret = generate_secret_value()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let insecure_copy_str = mock_secret
            .exposed_in_as_str_async(|str| async { (str.clone(), str) })
            .await;
        assert_eq!(
            insecure_copy_str.as_str(),
            mock_secret.sensitive_value_to_str().unwrap()
        );

        let insecure_copy_str = mock_secret
            .exposed_in_as_zstr_async(|str| async move { str.clone() })
            .await;
        assert_eq!(
            insecure_copy_str.as_str(),
            mock_secret.sensitive_value_to_str().unwrap()
        );
    }

    #[tokio::test]
    async fn exposed_function_str_async_closure() {
        let mut runner = TestRunner::default();
        let mock_secret = generate_secret_value()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let test_var_to_capture: String = "test-captured".to_string();

        let insecure_copy_str = mock_secret
            .exposed_in_as_str_async(|str| async {
                (format!("{}{}", test_var_to_capture, str), str)
            })
            .await;

        assert_eq!(
            insecure_copy_str.as_str(),
            format!(
                "{}{}",
                test_var_to_capture,
                mock_secret.sensitive_value_to_str().unwrap()
            )
        );
    }

    #[tokio::test]
    async fn exposed_function_vec_async() {
        let mut runner = TestRunner::default();
        let mock_secret = generate_secret_value()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let insecure_copy_vec = mock_secret
            .exposed_in_as_vec_async(|vec| async { (vec.clone(), vec) })
            .await;
        assert_eq!(&insecure_copy_vec, mock_secret.ref_sensitive_value());

        let insecure_copy_vec = mock_secret
            .exposed_in_as_zvec_async(|vec| async move { vec.clone() })
            .await;
        assert_eq!(insecure_copy_vec.deref(), mock_secret.ref_sensitive_value());
    }

    #[tokio::test]
    async fn exposed_function_vec_async_closure() {
        let mut runner = TestRunner::default();
        let mock_secret = generate_secret_value()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let test_var_to_capture: Vec<u8> = "test-captured".to_string().as_bytes().to_vec();

        let insecure_copy_vec = mock_secret
            .exposed_in_as_vec_async(|vec| async {
                ([test_var_to_capture.clone(), vec.clone()].concat(), vec)
            })
            .await;

        assert_eq!(
            insecure_copy_vec,
            [
                test_var_to_capture.clone(),
                mock_secret.ref_sensitive_value().to_vec()
            ]
            .concat()
        );
    }
}

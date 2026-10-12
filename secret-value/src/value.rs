use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::str::Utf8Error;
use zeroize::*;

/// A secret held as bytes and zeroized when it is dropped.
///
/// `Debug` and `Display` print `***`, so the value does not end up in logs or
/// panic messages. `Clone` makes a second buffer, and each copy is zeroized on
/// its own drop.
///
/// The value is read in two ways:
/// - borrowing it with `as_sensitive_*` and `ref_sensitive_value`, which make
///   no copy;
/// - lending a copy to a closure with `exposed_in_*`, which makes sure the
///   copy is zeroized once the closure is done with it.
///
/// ```
/// use secret_vault_value::SecretValue;
///
/// let secret_value = SecretValue::from("my-password");
/// assert_eq!(format!("{secret_value:?}"), "***");
/// assert_eq!(secret_value.to_string(), "***");
/// assert_eq!(secret_value.as_sensitive_str(), "my-password");
/// ```
#[derive(Zeroize, ZeroizeOnDrop, Eq, PartialEq, Default, Hash)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Takes ownership of `src` without copying it.
    pub fn new(src: Vec<u8>) -> Self {
        Self(src)
    }

    /// Borrows the secret bytes.
    pub fn ref_sensitive_value(&self) -> &Vec<u8> {
        &self.0
    }

    /// Borrows the secret bytes mutably.
    ///
    /// Be aware that growing the vector may reallocate it, and the old
    /// allocation is freed without being zeroized. Reserve the capacity up
    /// front if the value is built in place.
    pub fn ref_sensitive_value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    /// Borrows the secret as a string slice.
    ///
    /// # Errors
    ///
    /// Returns [`Utf8Error`] if the bytes are not valid UTF-8.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// assert!(SecretValue::from("my-password").sensitive_value_to_str().is_ok());
    /// assert!(SecretValue::new(vec![0xff]).sensitive_value_to_str().is_err());
    /// ```
    pub fn sensitive_value_to_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Zeroizes the bytes and leaves the value empty.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let mut secret_value = SecretValue::from("my-password");
    /// secret_value.secure_clear();
    /// assert!(secret_value.as_sensitive_bytes().is_empty());
    /// ```
    pub fn secure_clear(&mut self) {
        self.0.zeroize();
        self.0.clear();
    }

    /// Borrows the secret as a string slice.
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not valid UTF-8. Use
    /// [`sensitive_value_to_str`](Self::sensitive_value_to_str) for binary
    /// secrets.
    pub fn as_sensitive_str(&self) -> &str {
        self.sensitive_value_to_str().unwrap()
    }

    /// Borrows the secret bytes as a slice.
    pub fn as_sensitive_bytes(&self) -> &[u8] {
        self.ref_sensitive_value()
    }

    /// Lends a `String` copy of the secret to `f` and returns the first item of
    /// its result.
    ///
    /// `f` returns a pair `(T, Z)`: `T` is the result, `Z` is whatever must be
    /// zeroized once `f` returns, usually the `String` it was given. A copy
    /// that `f` neither returns as `Z` nor zeroizes itself is not zeroized.
    /// [`exposed_in_as_zstr`](Self::exposed_in_as_zstr) needs no such pair.
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not valid UTF-8.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::from("my-password");
    /// let length = secret_value.exposed_in_as_str(|password| (password.len(), password));
    /// assert_eq!(length, 11);
    /// ```
    pub fn exposed_in_as_str<T, Z: Zeroize, FN>(&self, f: FN) -> T
    where
        FN: Fn(String) -> (T, Z),
    {
        let decoded_as_string = self.sensitive_value_to_str().unwrap().to_string();
        let (result, mut zeroizable) = f(decoded_as_string);
        zeroizable.zeroize();
        result
    }

    /// Lends a [`Zeroizing<String>`] copy of the secret to `f` and returns its
    /// result.
    ///
    /// The copy is zeroized when `f` drops it.
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not valid UTF-8.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::from("my-password");
    /// let length = secret_value.exposed_in_as_zstr(|password| password.len());
    /// assert_eq!(length, 11);
    /// ```
    pub fn exposed_in_as_zstr<T, FN>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<String>) -> T,
    {
        let decoded_as_string = Zeroizing::new(self.sensitive_value_to_str().unwrap().to_string());
        f(decoded_as_string)
    }

    /// Lends a `Vec<u8>` copy of the secret to `f` and returns the first item
    /// of its result.
    ///
    /// The `(T, Z)` pair works as in
    /// [`exposed_in_as_str`](Self::exposed_in_as_str): `Z` is zeroized once
    /// `f` returns.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::new(vec![1, 2, 3]);
    /// let sum = secret_value.exposed_in_as_vec(|bytes| (bytes.iter().sum::<u8>(), bytes));
    /// assert_eq!(sum, 6);
    /// ```
    pub fn exposed_in_as_vec<T, Z: Zeroize, FN>(&self, f: FN) -> T
    where
        FN: Fn(Vec<u8>) -> (T, Z),
    {
        let (result, mut zeroizable) = f(self.0.clone());
        zeroizable.zeroize();
        result
    }

    /// Lends a [`Zeroizing<Vec<u8>>`] copy of the secret to `f` and returns
    /// its result.
    ///
    /// The copy is zeroized when `f` drops it.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// let secret_value = SecretValue::new(vec![1, 2, 3]);
    /// let sum = secret_value.exposed_in_as_zvec(|bytes| bytes.iter().sum::<u8>());
    /// assert_eq!(sum, 6);
    /// ```
    pub fn exposed_in_as_zvec<T, FN>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<Vec<u8>>) -> T,
    {
        f(Zeroizing::new(self.0.clone()))
    }

    /// Async form of [`exposed_in_as_str`](Self::exposed_in_as_str): `Z` is
    /// zeroized once the future returned by `f` completes.
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not valid UTF-8.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// async fn password_length(secret_value: &SecretValue) -> usize {
    ///     secret_value
    ///         .exposed_in_as_str_async(|password| async move { (password.len(), password) })
    ///         .await
    /// }
    /// # let runtime = tokio::runtime::Runtime::new().unwrap();
    /// # assert_eq!(runtime.block_on(password_length(&"my-password".into())), 11);
    /// ```
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

    /// Async form of [`exposed_in_as_zstr`](Self::exposed_in_as_zstr): the
    /// copy is zeroized when the future returned by `f` drops it.
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not valid UTF-8.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// async fn password_length(secret_value: &SecretValue) -> usize {
    ///     secret_value
    ///         .exposed_in_as_zstr_async(|password| async move { password.len() })
    ///         .await
    /// }
    /// # let runtime = tokio::runtime::Runtime::new().unwrap();
    /// # assert_eq!(runtime.block_on(password_length(&"my-password".into())), 11);
    /// ```
    pub async fn exposed_in_as_zstr_async<T, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<String>) -> FI,
        FI: Future<Output = T>,
    {
        let decoded_as_string = Zeroizing::new(self.sensitive_value_to_str().unwrap().to_string());
        f(decoded_as_string).await
    }

    /// Async form of [`exposed_in_as_vec`](Self::exposed_in_as_vec): `Z` is
    /// zeroized once the future returned by `f` completes.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// async fn key_length(secret_value: &SecretValue) -> usize {
    ///     secret_value
    ///         .exposed_in_as_vec_async(|key| async move { (key.len(), key) })
    ///         .await
    /// }
    /// # let runtime = tokio::runtime::Runtime::new().unwrap();
    /// # assert_eq!(runtime.block_on(key_length(&SecretValue::new(vec![1, 2, 3]))), 3);
    /// ```
    pub async fn exposed_in_as_vec_async<T, Z: Zeroize, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(Vec<u8>) -> FI,
        FI: Future<Output = (T, Z)>,
    {
        let (result, mut zeroizable) = f(self.0.clone()).await;
        zeroizable.zeroize();
        result
    }

    /// Async form of [`exposed_in_as_zvec`](Self::exposed_in_as_zvec): the
    /// copy is zeroized when the future returned by `f` drops it.
    ///
    /// ```
    /// use secret_vault_value::SecretValue;
    ///
    /// async fn key_length(secret_value: &SecretValue) -> usize {
    ///     secret_value
    ///         .exposed_in_as_zvec_async(|key| async move { key.len() })
    ///         .await
    /// }
    /// # let runtime = tokio::runtime::Runtime::new().unwrap();
    /// # assert_eq!(runtime.block_on(key_length(&SecretValue::new(vec![1, 2, 3]))), 3);
    /// ```
    pub async fn exposed_in_as_zvec_async<T, FN, FI>(&self, f: FN) -> T
    where
        FN: Fn(Zeroizing<Vec<u8>>) -> FI,
        FI: Future<Output = T>,
    {
        f(Zeroizing::new(self.0.clone())).await
    }
}

/// Copies the bytes and zeroizes the source `String`.
impl From<String> for SecretValue {
    fn from(mut str: String) -> Self {
        let result = Self(str.as_bytes().to_vec());
        str.zeroize();
        result
    }
}

/// Copies the bytes and zeroizes the caller's `String`, leaving it empty.
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

/// Copies the bytes and zeroizes the caller's `Vec`, leaving it empty.
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
            assert_eq!(format!("{mock_secret_value}"), "***");
            assert_eq!(format!("{mock_secret_value:?}"), "***");
            assert_eq!(format!("{mock_secret_value:#?}"), "***");
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
            .exposed_in_as_str_async(|str| async { (format!("{test_var_to_capture}{str}"), str) })
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

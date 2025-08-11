use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[allow(unused_variables)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let test_str1: String = "abd-abd".into();
    let mut test_vec = vec![1, 2, 3];

    let secret_value1: SecretValue = test_str1.into();
    let secret_value2: SecretValue = "abd-abd".into();
    let secret_value3: SecretValue = test_vec.clone().into();
    let secret_value4: SecretValue = (&mut test_vec).into();

    let secret_value5: SecretValue = bytes::BytesMut::from("test").into();

    let secret_string: &str = secret_value4.sensitive_value_to_str()?;
    let secret_vec: &Vec<u8> = secret_value4.ref_sensitive_value();

    let secret_string: Zeroizing<String> = secret_value1.as_sensitive_hex_str();
    let secret_string: Zeroizing<String> = secret_value1.as_sensitive_base64_str();

    let your_result_closure: YourType = secret_value4.exposed_in_as_str(|secret_value| {
        let some_result: YourType = YourType {
            _some_field: "test".to_string(),
        };
        (some_result, secret_value) // Returning back secret_value to zeroize
    });

    let your_result_json: YourType = secret_value4.expose_json_value_as::<YourType>()?;

    Ok(())
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
struct YourType {
    _some_field: String,
}

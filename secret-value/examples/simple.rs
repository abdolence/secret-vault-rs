use prost::Message;
use secret_vault_value::SecretValue;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize, Zeroize)]
struct DatabaseCredentials {
    user: String,
    password: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_value = SecretValue::from("my-password");
    println!("Debug: {secret_value:?}, Display: {secret_value}");

    let length = secret_value.exposed_in_as_zstr(|password| password.len());
    println!("Length from a zeroised copy: {length}");

    let hex = secret_value.as_sensitive_hex_str();
    let from_hex = SecretValue::from_hex_str(hex.to_string())?;
    println!(
        "Hex: {}, decodes back: {}",
        hex.as_str(),
        from_hex == secret_value
    );

    let base64 = secret_value.as_sensitive_base64_str();
    let from_base64 = SecretValue::from_base64_str(base64.to_string())?;
    println!(
        "Base64: {}, decodes back: {}",
        base64.as_str(),
        from_base64 == secret_value
    );

    let from_bytes = SecretValue::from(bytes::BytesMut::from("my-password"));
    println!("From BytesMut, equal: {}", from_bytes == secret_value);

    let json_value = SecretValue::from(r#"{"user":"admin","password":"my-password"}"#);
    let credentials = Zeroizing::new(json_value.expose_json_value_as::<DatabaseCredentials>()?);
    println!(
        "JSON user: {}, password length: {}",
        credentials.user,
        credentials.password.len()
    );

    let encoded = Zeroizing::new(secret_value.encode_to_vec());
    let decoded = SecretValue::decode(encoded.as_slice())?;
    println!(
        "Protobuf: {} bytes, decodes back: {}",
        encoded.len(),
        decoded == secret_value
    );

    Ok(())
}

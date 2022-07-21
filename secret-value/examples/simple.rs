use secret_vault_value::SecretValue;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let test_str1: String = "abd-abd".into();
    let mut test_vec = vec![1, 2, 3];

    let secret_value1: SecretValue = test_str1.into();
    let secret_value2: SecretValue = "abd-abd".into();
    let secret_value3: SecretValue = test_vec.clone().into();
    let secret_value4: SecretValue = (&mut test_vec).into();

    println!(
        "{}{}{}{}",
        secret_value1, secret_value2, secret_value3, secret_value4
    );

    Ok(())
}

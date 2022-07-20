use criterion::*;
use secret_vault::ring_encryption::SecretVaultRingAeadEncryption;
use secret_vault::*;
use secret_vault_value::SecretValue;

fn decrypt_secrets_perf_test(
    encryption: &SecretVaultRingAeadEncryption,
    encrypted_value: &EncryptedSecretValue,
    mock_secret_name: &SecretName,
) -> SecretVaultResult<SecretValue> {
    encryption.decrypt_value(&mock_secret_name, &encrypted_value)
}

fn criterion_benchmark(c: &mut Criterion) {
    let encryption = SecretVaultRingAeadEncryption::new().unwrap();
    let mock_secret_value = SecretValue::new("42".repeat(64).as_bytes().to_vec());
    let mock_secret_name: SecretName = "test".into();

    let encrypted_value = encryption
        .encrypt_value(&mock_secret_name, &mock_secret_value)
        .unwrap();

    c.bench_function("ring-decrypt-secret-value", |b| {
        b.iter(|| {
            decrypt_secrets_perf_test(
                black_box(&encryption),
                black_box(&encrypted_value),
                black_box(&mock_secret_name),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

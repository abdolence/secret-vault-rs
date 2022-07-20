#![allow(unused_parens, clippy::new_without_default)]

use criterion::*;

use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use secret_vault::locked_allocator::SecretVaultMemoryProtectAllocator;
use secret_vault::ring_encryption::SecretVaultRingAeadEncryption;
use secret_vault::*;
use secret_vault_value::SecretValue;

pub fn generate_secret_value() -> BoxedStrategy<SecretValue> {
    ("[a-zA-Z0-9]+")
        .prop_map(|(mock_secret_str)| SecretValue::new(mock_secret_str.as_bytes().to_vec()))
        .boxed()
}

pub fn generate_secret_ref() -> BoxedStrategy<SecretVaultRef> {
    ("[a-zA-Z0-9]+")
        .prop_map(|(mock_secret_name)| SecretVaultRef::new(mock_secret_name.into()))
        .boxed()
}

pub fn generate_mock_secrets_source() -> BoxedStrategy<MockSecretsSource> {
    prop::collection::vec(
        generate_secret_ref().prop_flat_map(move |secret_ref| {
            generate_secret_value().prop_map(move |secret_value| (secret_ref.clone(), secret_value))
        }),
        1..100,
    )
    .prop_map(|vec| MockSecretsSource::new(vec))
    .boxed()
}

fn read_secrets_perf_test<AR, E>(
    viewer: &SecretVaultSnapshot<AR, E>,
    secret_ref: &SecretVaultRef,
) -> SecretVaultResult<Option<SecretValue>>
where
    E: SecretVaultEncryption,
    AR: SecretVaultStoreValueAllocator,
{
    viewer.get_secret_by_ref(secret_ref)
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut runner = TestRunner::default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Creating runtime failed");

    let mock_secrets_store = generate_mock_secrets_source()
        .new_tree(&mut runner)
        .unwrap()
        .current();

    let mut simple_vault = SecretVaultBuilder::with_source(mock_secrets_store.clone())
        .without_encryption()
        .without_memory_protection()
        .build()
        .unwrap();

    let secret_ref = mock_secrets_store.secrets.keys().last().unwrap();

    let simple_vault_snapshot = rt.block_on(async {
        simple_vault
            .with_secrets_refs(mock_secrets_store.secrets.keys().into_iter().collect())
            .refresh()
            .await
            .unwrap();

        simple_vault.snapshot()
    });

    let mut vault_with_protection = SecretVaultBuilder::with_source(mock_secrets_store.clone())
        .without_encryption()
        .with_memory_protection(SecretVaultMemoryProtectAllocator)
        .build()
        .unwrap();

    let vault_with_protection_snapshot = rt.block_on(async {
        vault_with_protection
            .with_secrets_refs(mock_secrets_store.secrets.keys().into_iter().collect())
            .refresh()
            .await
            .unwrap();

        vault_with_protection.snapshot()
    });

    let mut vault_with_encryption = SecretVaultBuilder::with_source(mock_secrets_store.clone())
        .with_encryption(SecretVaultRingAeadEncryption::new().unwrap())
        .without_memory_protection()
        .build()
        .unwrap();

    let vault_with_encryption_snapshot = rt.block_on(async {
        vault_with_encryption
            .with_secrets_refs(mock_secrets_store.secrets.keys().into_iter().collect())
            .refresh()
            .await
            .unwrap();

        vault_with_encryption.snapshot()
    });

    c.bench_function("read-secrets-perf-simple-vault", |b| {
        b.iter(|| read_secrets_perf_test(black_box(&simple_vault_snapshot), black_box(secret_ref)))
    });
    c.bench_function("read-secrets-perf-memprotected-vault", |b| {
        b.iter(|| {
            read_secrets_perf_test(
                black_box(&vault_with_protection_snapshot),
                black_box(secret_ref),
            )
        })
    });
    c.bench_function("read-secrets-perf-encrypted-vault", |b| {
        b.iter(|| {
            read_secrets_perf_test(
                black_box(&vault_with_encryption_snapshot),
                black_box(secret_ref),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

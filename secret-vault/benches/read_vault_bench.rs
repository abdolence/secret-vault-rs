#![allow(unused_parens, clippy::new_without_default)]

use criterion::*;

use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use secret_vault::ring_encryption::SecretVaultRingAeadEncryption;
use secret_vault::*;
use secret_vault_value::SecretValue;
use std::hint::black_box;

pub fn generate_secret_value() -> BoxedStrategy<SecretValue> {
    ("[a-zA-Z0-9]+")
        .prop_map(|(mock_secret_str)| SecretValue::new(mock_secret_str.as_bytes().to_vec()))
        .boxed()
}

pub fn generate_secret_ref() -> BoxedStrategy<SecretVaultRef> {
    ("[a-zA-Z0-9]+")
        .prop_map(|(mock_secret_name)| {
            SecretVaultRef::new(mock_secret_name.into()).with_allow_in_snapshots(true)
        })
        .boxed()
}

pub fn generate_mock_secrets_source() -> BoxedStrategy<MockSecretsSource> {
    prop::collection::vec(
        generate_secret_ref().prop_flat_map(move |secret_ref| {
            generate_secret_value().prop_map(move |secret_value| (secret_ref.clone(), secret_value))
        }),
        1..1000,
    )
    .prop_map(|vec| MockSecretsSource::new(vec))
    .boxed()
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
        .build()
        .unwrap();

    let mock_store_keys: Vec<SecretVaultRef> = {
        let mock_store_secrets = mock_secrets_store.secrets.lock().unwrap();
        mock_store_secrets
            .keys()
            .into_iter()
            .map(|s| s.clone())
            .collect()
    };

    let secret_ref = mock_store_keys.last().unwrap();

    let simple_vault_snapshot = rt.block_on(async {
        simple_vault
            .register_secret_refs(mock_store_keys.iter().collect())
            .refresh()
            .await
            .unwrap();

        simple_vault.viewer()
    });

    let mut vault_with_encryption = SecretVaultBuilder::with_source(mock_secrets_store.clone())
        .with_encryption(SecretVaultRingAeadEncryption::new().unwrap())
        .build()
        .unwrap();

    let vault_with_encryption_viewer = rt.block_on(async {
        vault_with_encryption
            .register_secret_refs(mock_store_keys.iter().collect())
            .refresh()
            .await
            .unwrap();

        vault_with_encryption.viewer()
    });

    c.bench_function("read-secrets-perf-simple-vault", |b| {
        b.to_async(criterion::async_executor::FuturesExecutor)
            .iter(|| simple_vault_snapshot.get_secret_by_ref(black_box(secret_ref)))
    });

    c.bench_function("read-secrets-perf-encrypted-vault", |b| {
        b.to_async(criterion::async_executor::FuturesExecutor)
            .iter(|| vault_with_encryption_viewer.get_secret_by_ref(black_box(secret_ref)))
    });

    let vault_std_hash_snapshot = rt.block_on(async {
        vault_with_encryption
            .register_secret_refs(mock_store_keys.iter().collect())
            .refresh()
            .await
            .unwrap();

        vault_with_encryption
            .snapshot(SecretVaultHashMapSnapshotBuilder::new())
            .await
            .unwrap()
    });

    c.bench_function("read-secrets-perf-snapshot", |b| {
        b.iter(|| vault_std_hash_snapshot.get_secret_by_ref(black_box(&secret_ref)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

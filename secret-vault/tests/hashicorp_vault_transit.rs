//! Integration tests against a live Vault server with the Transit secrets engine at `transit/`.
//!
//! Ignored by default. Run them against a dev server:
//!
//! ```sh
//! docker run -d --rm --name vault-dev -p 8200:8200 \
//!     -e VAULT_DEV_ROOT_TOKEN_ID=dev-root docker.io/hashicorp/vault:latest
//! export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root VAULT_TRANSIT_KEY=secret-vault
//! curl -sf -H "X-Vault-Token: $VAULT_TOKEN" -d '{"type":"transit"}' "$VAULT_ADDR/v1/sys/mounts/transit"
//! curl -sf -H "X-Vault-Token: $VAULT_TOKEN" -X POST "$VAULT_ADDR/v1/transit/keys/$VAULT_TRANSIT_KEY"
//! cargo test -p secret-vault --features hashicorp-vault-transit,aws-lc --test hashicorp_vault_transit -- --ignored
//! ```

use rvstruct::ValueStruct;
use secret_vault::backends::AwsLc;
use secret_vault::hashicorp::{HcVaultTransitEnvelopeEncryption, HcVaultTransitKeyRef};
use secret_vault::*;
use secret_vault_value::SecretValue;

#[tokio::test]
#[ignore = "needs a Vault server with a Transit key; see the module docs"]
async fn value_round_trips_through_vault_transit_envelope_encryption() -> SecretVaultResult<()> {
    let key_name = std::env::var("VAULT_TRANSIT_KEY")
        .expect("VAULT_TRANSIT_KEY must name a Transit key to run the ignored Vault tests");
    let encryption =
        HcVaultTransitEnvelopeEncryption::<AwsLc>::new(&HcVaultTransitKeyRef::new(key_name))?;
    let secret_vault_key = SecretVaultKey::new(SecretName::from_static("my-app/database"));
    let secret_value = SecretValue::from("test-secret");

    let encrypted_value = encryption
        .encrypt_value(&secret_vault_key, &secret_value)
        .await?;
    assert_ne!(encrypted_value.value(), secret_value.ref_sensitive_value());

    let decrypted_value = encryption
        .decrypt_value(&secret_vault_key, &encrypted_value)
        .await?;
    assert_eq!(decrypted_value, secret_value);
    Ok(())
}

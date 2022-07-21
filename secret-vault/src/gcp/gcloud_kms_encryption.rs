use gcloud_sdk::*;
use rsb_derive::*;
use rvstruct::ValueStruct;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use tracing::*;

use crate::ring_encryption_support::*;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::{DecryptRequest, EncryptRequest};
use ring::rand::SystemRandom;
use secret_vault_value::SecretValue;
use tonic::metadata::MetadataValue;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct GoogleKmsKeyRef {
    pub google_project_id: String,
    pub location: String,
    pub key_ring: String,
    pub key: String,
}

impl GoogleKmsKeyRef {
    fn to_google_ref(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.google_project_id, self.location, self.key_ring, self.key
        )
    }
}

pub struct GoogleKmsEnvelopeEncryption {
    kms_client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    kms_key_ref: GoogleKmsKeyRef,
    algo: &'static ring::aead::Algorithm,
    wrapped_session_secret: WrappedSessionKey,
    nonce_data: SecretValue,
}

impl GoogleKmsEnvelopeEncryption {
    pub async fn new(kms_key_ref: &GoogleKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_algorithm(kms_key_ref, &ring::aead::CHACHA20_POLY1305).await
    }

    pub async fn with_algorithm(
        kms_key_ref: &GoogleKmsKeyRef,
        algo: &'static ring::aead::Algorithm,
    ) -> SecretVaultResult<Self> {
        debug!(
            "Initialising Google KMS envelope encryption for {}",
            kms_key_ref.to_google_ref()
        );

        let client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                KeyManagementServiceClient::new,
                "https://cloudkms.googleapis.com",
                None,
            )
            .await
            .map_err(|e| SecretVaultError::from(e))?;

        let secure_rand = SystemRandom::new();

        let wrapped_session_secret = Self::encrypt_with_kms(
            &client,
            kms_key_ref,
            generate_session_secret(&secure_rand, algo.key_len())?,
        )
        .await?;

        Ok(Self {
            kms_client: client,
            kms_key_ref: kms_key_ref.clone(),
            algo,
            wrapped_session_secret,
            nonce_data: generate_nonce(&secure_rand)?,
        })
    }

    async fn encrypt_with_kms(
        client: &GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
        kms_key_ref: &GoogleKmsKeyRef,
        session_key: SecretValue,
    ) -> SecretVaultResult<WrappedSessionKey> {
        let mut encrypt_request = tonic::Request::new(EncryptRequest {
            name: kms_key_ref.to_google_ref(),
            plaintext: hex::encode(session_key.ref_sensitive_value().as_slice()).into_bytes(),
            ..Default::default()
        });

        encrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                "name={}",
                kms_key_ref.to_google_ref()
            ))
            .unwrap(),
        );

        let encrypt_response = client
            .get()
            .encrypt(encrypt_request)
            .await
            .map_err(|e| SecretVaultError::from(e))?;

        Ok(WrappedSessionKey(secret_vault_value::SecretValue::new(
            encrypt_response.into_inner().ciphertext,
        )))
    }

    async fn unwrap_session_key(&self) -> SecretVaultResult<SecretValue> {
        let mut decrypt_request = tonic::Request::new(DecryptRequest {
            name: self.kms_key_ref.to_google_ref(),
            ciphertext: self
                .wrapped_session_secret
                .value()
                .ref_sensitive_value()
                .clone(),
            ..Default::default()
        });

        decrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                "name={}",
                self.kms_key_ref.to_google_ref()
            ))
            .unwrap(),
        );

        let decrypt_response = self
            .kms_client
            .get()
            .decrypt(decrypt_request)
            .await
            .map_err(|e| SecretVaultError::from(e))?;

        Ok(secret_vault_value::SecretValue::new(
            hex::decode(decrypt_response.into_inner().plaintext).unwrap(),
        ))
    }
}

#[async_trait]
impl SecretVaultEncryption for GoogleKmsEnvelopeEncryption {
    async fn encrypt_value(
        &self,
        secret_name: &SecretName,
        secret_value: &SecretValue,
    ) -> SecretVaultResult<EncryptedSecretValue> {
        let session_key = self.unwrap_session_key().await?;
        encrypt_with_sealing_key(
            self.algo,
            &session_key,
            &self.nonce_data,
            secret_name,
            secret_value,
        )
    }

    async fn decrypt_value(
        &self,
        secret_name: &SecretName,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> SecretVaultResult<SecretValue> {
        let session_key = self.unwrap_session_key().await?;
        decrypt_with_opening_key(
            self.algo,
            &session_key,
            &self.nonce_data,
            secret_name,
            encrypted_secret_value,
        )
    }
}

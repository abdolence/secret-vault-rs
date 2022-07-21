use rsb_derive::*;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use aws_sdk_kms::types::Blob;
use tracing::*;

use crate::ring_encryption_support::*;
use ring::rand::SystemRandom;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AwsKmsKeyRef {
    pub account_id: String,
    pub key_id: String,
    pub aws_region: Option<aws_sdk_secretsmanager::Region>,
}

impl AwsKmsKeyRef {
    pub fn to_key_arn(&self) -> String {
        self.aws_region
            .as_ref()
            .map(|region| {
                format!(
                    "arn:aws:kms:{}:{}:key/{}",
                    region, self.account_id, self.key_id
                )
            })
            .unwrap_or_else(|| self.key_id.clone())
    }
}

pub struct AwsKmsEnvelopeEncryption {
    aws_key_ref: AwsKmsKeyRef,
    client: aws_sdk_kms::Client,
    algo: &'static ring::aead::Algorithm,
    wrapped_session_secret: WrappedSessionKey,
    nonce_data: SecretValue,
}

impl AwsKmsEnvelopeEncryption {
    pub async fn new(kms_key_ref: &AwsKmsKeyRef) -> SecretVaultResult<Self> {
        Self::with_algorithm(kms_key_ref, &ring::aead::CHACHA20_POLY1305).await
    }

    pub async fn with_algorithm(
        kms_key_ref: &AwsKmsKeyRef,
        algo: &'static ring::aead::Algorithm,
    ) -> SecretVaultResult<Self> {
        debug!(
            "Initialising AWS KMS envelope encryption for {}",
            kms_key_ref.to_key_arn()
        );

        let shared_config = aws_config::load_from_env().await;

        let effective_kms_ref = if kms_key_ref.aws_region.is_none() {
            kms_key_ref
                .clone()
                .opt_aws_region(shared_config.region().cloned())
        } else {
            kms_key_ref.clone()
        };

        let client = aws_sdk_kms::Client::new(&shared_config);
        let secure_rand = SystemRandom::new();

        let wrapped_session_secret = Self::encrypt_with_kms(
            &client,
            &effective_kms_ref,
            generate_session_secret(&secure_rand, algo.key_len())?,
        )
        .await?;

        Ok(Self {
            aws_key_ref: effective_kms_ref,
            client,
            algo,
            wrapped_session_secret,
            nonce_data: generate_nonce(&secure_rand)?,
        })
    }

    async fn encrypt_with_kms(
        client: &aws_sdk_kms::Client,
        kms_key_ref: &AwsKmsKeyRef,
        session_key: SecretValue,
    ) -> SecretVaultResult<WrappedSessionKey> {
        match client
            .encrypt()
            .set_key_id(Some(kms_key_ref.to_key_arn()))
            .set_plaintext(Some(Blob::new(
                hex::encode(session_key.ref_sensitive_value().as_slice()).into_bytes(),
            )))
            .send()
            .await
        {
            Ok(encrypt_response) => {
                if let Some(blob) = encrypt_response.ciphertext_blob {
                    Ok(WrappedSessionKey(secret_vault_value::SecretValue::new(
                        blob.into_inner(),
                    )))
                } else {
                    error!(
                        "Unable to encrypt DEK with AWS KMS {}: Didn't receive any blob.",
                        kms_key_ref.to_key_arn()
                    );
                    return Err(SecretVaultError::EncryptionError(
                        SecretVaultEncryptionError::new(
                            SecretVaultErrorPublicGenericDetails::new("AWS_ERROR".into()),
                            format!(
                                "AWS error {:?}. No encrypted blob received.",
                                kms_key_ref.to_key_arn()
                            ),
                        ),
                    ));
                }
            }
            Err(err) => {
                error!(
                    "Unable to encrypt DEK with AWS KMS {}: {}.",
                    kms_key_ref.to_key_arn(),
                    err
                );
                return Err(SecretVaultError::EncryptionError(
                    SecretVaultEncryptionError::new(
                        SecretVaultErrorPublicGenericDetails::new("AWS_ERROR".into()),
                        format!("AWS error {:?}: {}", kms_key_ref.to_key_arn(), err),
                    ),
                ));
            }
        }
    }

    async fn unwrap_session_key(&self) -> SecretVaultResult<SecretValue> {
        let decrypt_response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(
                self.wrapped_session_secret
                    .value()
                    .ref_sensitive_value()
                    .as_slice(),
            ))
            .send()
            .await
            .map_err(|err| SecretVaultError::from(err))?;

        if let Some(plaintext) = decrypt_response.plaintext {
            Ok(secret_vault_value::SecretValue::new(
                hex::decode(plaintext.into_inner()).unwrap(),
            ))
        } else {
            Err(SecretVaultError::EncryptionError(
                SecretVaultEncryptionError::new(
                    SecretVaultErrorPublicGenericDetails::new("AWS_ERROR".into()),
                    format!(
                        "AWS error {:?}: No plaintext received",
                        self.aws_key_ref.to_key_arn()
                    ),
                ),
            ))
        }
    }
}

#[async_trait]
impl SecretVaultEncryption for AwsKmsEnvelopeEncryption {
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

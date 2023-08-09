use rsb_derive::Builder;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum SecretVaultError {
    SystemError(SecretVaultSystemError),
    DataNotFoundError(SecretVaultDataNotFoundError),
    InvalidParametersError(SecretVaultInvalidParametersError),
    NetworkError(SecretVaultNetworkError),
    EncryptionError(SecretVaultEncryptionError),
    SecretsSourceError(SecretsSourceError),
}

impl Display for SecretVaultError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match *self {
            SecretVaultError::SystemError(ref err) => err.fmt(f),
            SecretVaultError::DataNotFoundError(ref err) => err.fmt(f),
            SecretVaultError::InvalidParametersError(ref err) => err.fmt(f),
            SecretVaultError::NetworkError(ref err) => err.fmt(f),
            SecretVaultError::EncryptionError(ref err) => err.fmt(f),
            SecretVaultError::SecretsSourceError(ref err) => err.fmt(f),
        }
    }
}

impl std::error::Error for SecretVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            SecretVaultError::SystemError(ref err) => Some(err),
            SecretVaultError::DataNotFoundError(ref err) => Some(err),
            SecretVaultError::InvalidParametersError(ref err) => Some(err),
            SecretVaultError::NetworkError(ref err) => Some(err),
            SecretVaultError::EncryptionError(ref err) => Some(err),
            SecretVaultError::SecretsSourceError(ref err) => Some(err),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretVaultErrorPublicGenericDetails {
    pub code: String,
}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
pub struct SecretVaultSystemError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub message: String,
}

impl Display for SecretVaultSystemError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "SecretVault system/internal error: {:?} / {}",
            self.public, self.message
        )
    }
}

impl std::error::Error for SecretVaultSystemError {}

#[derive(Debug, Clone, Builder)]
pub struct SecretVaultDatabaseError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub details: String,
    pub retry_possible: bool,
}

impl Display for SecretVaultDatabaseError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Database general error occurred: {:?} / {}",
            self.public, self.details
        )
    }
}

impl std::error::Error for SecretVaultDatabaseError {}

#[derive(Debug, Clone, Builder)]
pub struct SecretVaultDataConflictError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub details: String,
}

impl Display for SecretVaultDataConflictError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Database conflict error occurred: {:?} / {}",
            self.public, self.details
        )
    }
}

impl std::error::Error for SecretVaultDataConflictError {}

#[derive(Debug, Clone, Builder)]
pub struct SecretVaultDataNotFoundError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub data_detail_message: String,
}

impl Display for SecretVaultDataNotFoundError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Data not found error occurred: {:?}", self.public)
    }
}

impl std::error::Error for SecretVaultDataNotFoundError {}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretVaultInvalidParametersPublicDetails {
    pub field: String,
    pub error: String,
}

#[derive(Debug, Clone, Builder)]
pub struct SecretVaultInvalidParametersError {
    pub public: SecretVaultInvalidParametersPublicDetails,
}

impl Display for SecretVaultInvalidParametersError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Data not found error occurred: {:?}", self.public)
    }
}

impl std::error::Error for SecretVaultInvalidParametersError {}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretVaultInvalidJsonErrorPublicDetails {
    pub code: String,
}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
pub struct SecretVaultNetworkError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub message: String,
}

impl Display for SecretVaultNetworkError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Network error: {:?} / {}", self.public, self.message)
    }
}

impl std::error::Error for SecretVaultNetworkError {}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
pub struct SecretVaultEncryptionError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub message: String,
}

impl SecretVaultEncryptionError {
    pub fn create(code: &str, message: &str) -> SecretVaultError {
        SecretVaultError::EncryptionError(SecretVaultEncryptionError::new(
            SecretVaultErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }
}

impl Display for SecretVaultEncryptionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "SecretVault encryption error: {:?} / {}",
            self.public, self.message
        )
    }
}

impl std::error::Error for SecretVaultEncryptionError {}

#[derive(Debug, Builder)]
pub struct SecretsSourceError {
    pub public: SecretVaultErrorPublicGenericDetails,
    pub message: String,
    pub root_cause: Option<BoxedError>,
}

impl Display for SecretsSourceError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "SecretVault source error: {:?} / {}",
            self.public, self.message
        )
    }
}

impl std::error::Error for SecretsSourceError {}

#[cfg(feature = "gcp")]
impl From<gcloud_sdk::error::Error> for SecretVaultError {
    fn from(e: gcloud_sdk::error::Error) -> Self {
        SecretVaultError::SecretsSourceError(
            SecretsSourceError::new(
                SecretVaultErrorPublicGenericDetails::new(format!("{:?}", e.kind())),
                format!("GCloud system error: {e}"),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(feature = "gcp")]
impl From<tonic::Status> for SecretVaultError {
    fn from(status: tonic::Status) -> Self {
        match status.code() {
            tonic::Code::NotFound => {
                SecretVaultError::DataNotFoundError(SecretVaultDataNotFoundError::new(
                    SecretVaultErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                    format!("{status}"),
                ))
            }
            tonic::Code::Aborted
            | tonic::Code::Cancelled
            | tonic::Code::Unavailable
            | tonic::Code::ResourceExhausted => {
                SecretVaultError::NetworkError(SecretVaultNetworkError::new(
                    SecretVaultErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                    format!("{status}"),
                ))
            }
            _ => SecretVaultError::NetworkError(SecretVaultNetworkError::new(
                SecretVaultErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                format!("{status}"),
            )),
        }
    }
}

#[cfg(feature = "aws-secretmanager")]
impl<E: Display + Error + Sync + Send + 'static, R: std::fmt::Debug + Sync + Send + 'static>
    From<aws_sdk_secretsmanager::error::SdkError<E, R>> for SecretVaultError
{
    fn from(e: aws_sdk_secretsmanager::error::SdkError<E, R>) -> Self {
        SecretVaultError::SecretsSourceError(
            SecretsSourceError::new(
                SecretVaultErrorPublicGenericDetails::new(format!("{e}")),
                format!("AWS error: {e}"),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(not(feature = "aws-secretmanager"))]
#[cfg(feature = "aws-kms-encryption")]
impl<E: Display + Error + Sync + Send + 'static, R: std::fmt::Debug + Sync + Send + 'static>
    From<aws_sdk_kms::error::SdkError<E, R>> for SecretVaultError
{
    fn from(e: aws_sdk_kms::error::SdkError<E, R>) -> Self {
        SecretVaultError::SecretsSourceError(
            SecretsSourceError::new(
                SecretVaultErrorPublicGenericDetails::new(format!("{e}")),
                format!("AWS KMS error: {e}"),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(any(feature = "kms", feature = "ring-aead-encryption"))]
impl From<kms_aead::errors::KmsAeadError> for SecretVaultError {
    fn from(e: kms_aead::errors::KmsAeadError) -> Self {
        SecretVaultError::EncryptionError(SecretVaultEncryptionError::new(
            SecretVaultErrorPublicGenericDetails::new(format!("{e:?}")),
            format!("KMS error: {e}"),
        ))
    }
}

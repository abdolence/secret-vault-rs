use rsb_derive::Builder;
use serde::*;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Debug)]
pub enum SecretManagerError {
    SystemError(SecretManagerSystemError),
    DataNotFoundError(SecretManagerDataNotFoundError),
    InvalidParametersError(SecretManagerInvalidParametersError),
    InvalidJsonError(SecretManagerInvalidJsonError),
    NetworkError(SecretManagerNetworkError),
}

impl Display for SecretManagerError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match *self {
            SecretManagerError::SystemError(ref err) => err.fmt(f),
            SecretManagerError::DataNotFoundError(ref err) => err.fmt(f),
            SecretManagerError::InvalidParametersError(ref err) => err.fmt(f),
            SecretManagerError::InvalidJsonError(ref err) => err.fmt(f),
            SecretManagerError::NetworkError(ref err) => err.fmt(f),
        }
    }
}

impl Error for SecretManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            SecretManagerError::SystemError(ref err) => Some(err),
            SecretManagerError::DataNotFoundError(ref err) => Some(err),
            SecretManagerError::InvalidParametersError(ref err) => Some(err),
            SecretManagerError::InvalidJsonError(ref err) => Some(err),
            SecretManagerError::NetworkError(ref err) => Some(err),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Builder, Serialize, Deserialize)]
pub struct SecretManagerErrorPublicGenericDetails {
    pub code: String,
}

#[derive(Debug, PartialEq, Clone, Builder)]
pub struct SecretManagerSystemError {
    pub public: SecretManagerErrorPublicGenericDetails,
    pub message: String,
}

impl Display for SecretManagerSystemError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "SecretManager system/internal error: {}", self.message)
    }
}

impl std::error::Error for SecretManagerSystemError {}

#[derive(Debug, Clone, Builder)]
pub struct SecretManagerDatabaseError {
    pub public: SecretManagerErrorPublicGenericDetails,
    pub details: String,
    pub retry_possible: bool,
}

impl Display for SecretManagerDatabaseError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Database general error occurred: {}", self.details)
    }
}

impl std::error::Error for SecretManagerDatabaseError {}

#[derive(Debug, Clone, Builder)]
pub struct SecretManagerDataConflictError {
    pub public: SecretManagerErrorPublicGenericDetails,
    pub details: String,
}

impl Display for SecretManagerDataConflictError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Database conflict error occurred: {}", self.details)
    }
}

impl std::error::Error for SecretManagerDataConflictError {}

#[derive(Debug, Clone, Builder)]
pub struct SecretManagerDataNotFoundError {
    pub public: SecretManagerErrorPublicGenericDetails,
    pub data_detail_message: String,
}

impl Display for SecretManagerDataNotFoundError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Data not found error occurred: {:?}", self.public)
    }
}

impl std::error::Error for SecretManagerDataNotFoundError {}

#[derive(Debug, PartialEq, Clone, Builder, Serialize, Deserialize)]
pub struct SecretManagerInvalidParametersPublicDetails {
    pub field: String,
    pub error: String,
}

#[derive(Debug, Clone, Builder)]
pub struct SecretManagerInvalidParametersError {
    pub public: SecretManagerInvalidParametersPublicDetails,
}

impl Display for SecretManagerInvalidParametersError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Data not found error occurred: {:?}", self.public)
    }
}

impl std::error::Error for SecretManagerInvalidParametersError {}

#[derive(Debug, PartialEq, Clone, Builder, Serialize, Deserialize)]
pub struct SecretManagerInvalidJsonErrorPublicDetails {
    pub code: String,
}

#[derive(Debug, Builder)]
pub struct SecretManagerInvalidJsonError {
    pub public: SecretManagerInvalidJsonErrorPublicDetails,
    pub details: serde_json::Error,
}

impl Display for SecretManagerInvalidJsonError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Invalid JSON: {:?}", self.public)
    }
}

impl std::error::Error for SecretManagerInvalidJsonError {}

#[derive(Debug, PartialEq, Clone, Builder)]
pub struct SecretManagerNetworkError {
    pub public: SecretManagerErrorPublicGenericDetails,
    pub message: String,
}

impl Display for SecretManagerNetworkError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Network error: {}", self.message)
    }
}

impl std::error::Error for SecretManagerNetworkError {}

impl From<gcloud_sdk::error::Error> for SecretManagerError {
    fn from(e: gcloud_sdk::error::Error) -> Self {
        SecretManagerError::SystemError(SecretManagerSystemError::new(
            SecretManagerErrorPublicGenericDetails::new(format!("{:?}", e.kind())),
            format!("GCloud system error: {}", e),
        ))
    }
}

impl From<serde_json::Error> for SecretManagerError {
    fn from(e: serde_json::Error) -> Self {
        SecretManagerError::InvalidJsonError(SecretManagerInvalidJsonError::new(
            SecretManagerInvalidJsonErrorPublicDetails::new(format!(
                "SecretManager json parse error: {:?}",
                e.classify()
            )),
            e,
        ))
    }
}

impl From<tonic::Status> for SecretManagerError {
    fn from(status: tonic::Status) -> Self {
        match status.code() {
            tonic::Code::NotFound => {
                SecretManagerError::DataNotFoundError(SecretManagerDataNotFoundError::new(
                    SecretManagerErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                    format!("{}", status),
                ))
            }
            tonic::Code::Unknown => check_hyper_errors(status),
            _ => SecretManagerError::SystemError(SecretManagerSystemError::new(
                SecretManagerErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                format!("{}", status)
            )),
        }
    }
}

fn check_hyper_errors(status: tonic::Status) -> SecretManagerError {
    match status.source() {
        Some(hyper_error) => match hyper_error.downcast_ref::<hyper::Error>() {
            Some(err) if err.is_closed() => {
                SecretManagerError::NetworkError(SecretManagerNetworkError::new(
                    SecretManagerErrorPublicGenericDetails::new("CONNECTION_CLOSED".into()),
                    format!("Hyper error: {}", err)
                ))
            }
            Some(err) if err.is_timeout() => {
                SecretManagerError::NetworkError(SecretManagerNetworkError::new(
                    SecretManagerErrorPublicGenericDetails::new("CONNECTION_TIMEOUT".into()),
                    format!("Hyper error: {}", err),
                ))
            }
            Some(err) => SecretManagerError::NetworkError(SecretManagerNetworkError::new(
                SecretManagerErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                format!("Hyper error: {}", err),
            )),
            _ => SecretManagerError::NetworkError(SecretManagerNetworkError::new(
                SecretManagerErrorPublicGenericDetails::new(format!("{:?}", status.code())),
                format!("{}", status)
            )),
        },
        _ => SecretManagerError::NetworkError(SecretManagerNetworkError::new(
            SecretManagerErrorPublicGenericDetails::new(format!("{:?}", status.code())),
            format!("{}", status),
        )),
    }
}

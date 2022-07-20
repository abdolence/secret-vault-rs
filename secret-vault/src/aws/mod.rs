#[cfg(feature = "aws-secretmanager")]
mod aws_secret_manager_source;
#[cfg(feature = "aws-secretmanager")]
pub use aws_secret_manager_source::AmazonSecretManagerSource;

#[cfg(feature = "gcloud-secretmanager")]
mod gcloud_secret_manager_source;
#[cfg(feature = "gcloud-secretmanager")]
pub use gcloud_secret_manager_source::GoogleSecretManagerSource;

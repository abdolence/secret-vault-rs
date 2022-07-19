#[cfg(feature = "gcloud-secretmanager")]
mod gcloud_secret_manager_source;

pub use gcloud_secret_manager_source::GoogleSecretManagerSource;

use crate::*;
use rsb_derive::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::*;
use tracing::*;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Builder)]
pub struct SecretVaultAutoRefresherOptions {
    pub refresh_interval: Duration,
}

pub struct SecretVaultAutoRefresher<S, E>
where
    S: SecretsSource + Send + Sync,
    E: SecretVaultEncryption + Sync + Send,
{
    vault: Arc<SecretVault<S, E>>,
    options: SecretVaultAutoRefresherOptions,
    shutdown: Arc<AtomicBool>,
    shutdown_handle: Option<JoinHandle<()>>,
    shutdown_writer: Option<Arc<UnboundedSender<i8>>>,
}

impl<S, E> SecretVaultAutoRefresher<S, E>
where
    S: SecretsSource + 'static + Send + Sync,
    E: SecretVaultEncryption + Sync + Send + 'static,
{
    pub fn new(vault: Arc<SecretVault<S, E>>, options: SecretVaultAutoRefresherOptions) -> Self {
        Self {
            vault,
            options,
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_handle: None,
            shutdown_writer: None,
        }
    }

    pub async fn start(&mut self) -> SecretVaultResult<()> {
        info!(
            "Starting SecretVault automatic refreshing: {:?}",
            self.options
        );

        let (tx, rx): (UnboundedSender<i8>, UnboundedReceiver<i8>) =
            tokio::sync::mpsc::unbounded_channel();

        self.shutdown_writer = Some(Arc::new(tx));

        self.shutdown_handle = Some(tokio::spawn(Self::refresh(
            self.vault.clone(),
            self.options.clone(),
            self.shutdown.clone(),
            rx,
        )));

        Ok(())
    }

    pub async fn shutdown(&mut self) -> SecretVaultResult<()> {
        debug!("Shutting down secret vault refresher ...");
        self.shutdown.store(true, Ordering::Relaxed);

        if let Some(shutdown_writer) = self.shutdown_writer.take() {
            shutdown_writer.send(1).ok();
        }
        if let Some(signaller) = self.shutdown_handle.take() {
            signaller.await.expect("The task being joined has panicked");
        }
        info!("Shutting down secret vault refresher has been finished...");
        Ok(())
    }

    async fn refresh(
        vault: Arc<SecretVault<S, E>>,
        options: SecretVaultAutoRefresherOptions,
        shutdown_flag: Arc<AtomicBool>,
        mut shutdown_receiver: UnboundedReceiver<i8>,
    ) {
        let mut interval = interval(options.refresh_interval);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_receiver.recv() => {
                    trace!("Exiting from auto refresh thread...");
                    shutdown_receiver.close();
                    break;
                },
                _ = interval.tick() => {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        trace!("Exiting from auto refresh thread...");
                        shutdown_receiver.close();
                        break;
                    }
                    match vault.refresh_only(|secret_ref| secret_ref.auto_refresh).await {
                        Ok(_) => {},
                        Err(err) => {
                            warn!("Automatic refresh vault error: {}", err);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::source_tests::*;
    use crate::*;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn auto_refresh_vault_test() {
        let mut runner = TestRunner::default();
        let mock_secrets_store = generate_mock_secrets_source()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let secret_refs: Vec<SecretVaultRef> = mock_secrets_store
            .secrets
            .keys()
            .into_iter()
            .cloned()
            .map(|secret_ref| secret_ref.with_auto_refresh(true))
            .collect();

        let vault = Arc::new(
            SecretVaultBuilder::with_source(mock_secrets_store.clone())
                .build()
                .unwrap()
                .with_secrets_refs(secret_refs.iter().collect()),
        );

        let mut refresher = SecretVaultAutoRefresher::new(
            vault.clone(),
            SecretVaultAutoRefresherOptions::new(Duration::from_millis(50)),
        );

        refresher.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        refresher.shutdown().await.unwrap();

        for secret_ref in secret_refs {
            assert_eq!(
                vault
                    .get_secret_by_ref(&secret_ref)
                    .await
                    .unwrap()
                    .map(|secret| secret.value)
                    .as_ref(),
                mock_secrets_store.secrets.get(&secret_ref)
            )
        }
    }
}

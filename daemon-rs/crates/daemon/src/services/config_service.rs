use std::{io::ErrorKind, path::Path, sync::Arc};

use anyhow::Result;
use tokio::sync::watch;

use crate::config::Config;
use crate::utils::time_nonce::unique_name;

#[derive(Clone)]
pub struct ConfigService {
    snapshot_tx: watch::Sender<Arc<Config>>,
    snapshot_rx: watch::Receiver<Arc<Config>>,
}

impl ConfigService {
    fn publish_config_snapshot(&self, config: Config) {
        let _ = self.snapshot_tx.send(Arc::new(config));
    }

    fn parse_raw_json_with_base(base: &Config, raw_json: &str) -> Result<Config> {
        let mut parsed = Config::from_raw_json(&base.config_path, raw_json.to_string())?;
        let log_level_present = serde_json::from_str::<serde_json::Value>(raw_json)
            .ok()
            .and_then(|value| {
                value
                    .as_object()
                    .map(|obj| obj.keys().any(|key| key.eq_ignore_ascii_case("LogLevel")))
            })
            .unwrap_or(false);
        if !log_level_present {
            parsed.log_level = base.log_level;
        }
        Ok(parsed)
    }

    async fn persist_raw_json_at(path: &Path, raw_json: &str) -> Result<()> {
        let tmp_path = path.with_extension(unique_name("tmp"));
        tracing::debug!(path = %path.display(), tmp = %tmp_path.display(), "persisting raw config payload");

        tokio::fs::write(&tmp_path, raw_json).await?;
        if let Err(err) = tokio::fs::rename(&tmp_path, path).await {
            if let Err(remove_err) = tokio::fs::remove_file(&tmp_path).await
                && remove_err.kind() != ErrorKind::NotFound
            {
                tracing::warn!(%remove_err, path = %tmp_path.display(), "failed to cleanup temporary config file after persist failure");
            }
            return Err(err.into());
        }

        Ok(())
    }

    pub fn new(config: Config) -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(config));
        Self {
            snapshot_tx,
            snapshot_rx,
        }
    }

    pub fn snapshot_arc(&self) -> Arc<Config> {
        self.snapshot_rx.borrow().clone()
    }

    pub async fn reload(&self) -> Result<Config> {
        let current = self.snapshot_arc();
        let path = current.config_path.as_path();
        tracing::debug!(path = %path.display(), "loading config from disk");
        let raw_json = tokio::fs::read_to_string(path).await?;
        let config = Config::from_raw_json(path, raw_json)?;
        tracing::info!(
            addr = %config.client_addr,
            log_level = config.log_level,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "config loaded from disk"
        );
        self.publish_config_snapshot(config.clone());
        Ok(config)
    }

    #[cfg(test)]
    pub async fn apply_raw_json(&self, raw_json: &str) -> Result<Config> {
        let current = self.snapshot_arc();
        let mut config = Self::parse_raw_json_with_base(current.as_ref(), raw_json)?;
        Self::persist_raw_json_at(&current.config_path, raw_json).await?;
        config.config_path = current.config_path.clone();
        tracing::info!(
            addr = %config.client_addr,
            log_level = config.log_level,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "config payload applied"
        );
        self.publish_config_snapshot(config.clone());
        Ok(config)
    }

    pub async fn parse_raw_json(&self, raw_json: &str) -> Result<Config> {
        let current = self.snapshot_arc();
        Self::parse_raw_json_with_base(current.as_ref(), raw_json)
    }

    pub async fn persist_raw_json(&self, raw_json: &str) -> Result<()> {
        let current = self.snapshot_arc();
        Self::persist_raw_json_at(current.config_path.as_path(), raw_json).await
    }

    pub async fn set_snapshot(&self, config: Config) {
        self.publish_config_snapshot(config);
    }

    pub async fn set_log_level(&self, level: u32) {
        let mut updated = Arc::unwrap_or_clone(self.snapshot_arc());
        updated.log_level = level;
        self.publish_config_snapshot(updated);
    }
}

use std::{io::ErrorKind, sync::Arc};

use anyhow::Result;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::utils::time_nonce::unique_name;

#[derive(Clone)]
pub struct ConfigService {
    current: Arc<RwLock<Config>>,
}

impl ConfigService {
    pub fn new(config: Config) -> Self {
        Self {
            current: Arc::new(RwLock::new(config)),
        }
    }

    pub async fn snapshot(&self) -> Config {
        self.current.read().await.clone()
    }

    pub async fn default_action(&self) -> crate::config::DefaultAction {
        self.current.read().await.default_action
    }

    pub async fn default_duration(&self) -> crate::config::DefaultDuration {
        self.current.read().await.default_duration
    }

    pub async fn intercept_unknown(&self) -> bool {
        self.current.read().await.intercept_unknown
    }

    pub async fn reload(&self) -> Result<Config> {
        let path = self.current.read().await.config_path.clone();
        tracing::debug!(path = %path.display(), "loading config from disk");
        let raw_json = tokio::fs::read_to_string(&path).await?;
        let config = Config::from_raw_json(&path, raw_json)?;
        tracing::info!(
            addr = %config.client_addr,
            log_level = config.log_level,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "config loaded from disk"
        );
        *self.current.write().await = config.clone();
        Ok(config)
    }

    #[cfg(test)]
    pub async fn apply_raw_json(&self, raw_json: &str) -> Result<Config> {
        let mut config = self.parse_raw_json(raw_json).await?;
        self.persist_raw_json(raw_json).await?;
        let path = self.current.read().await.config_path.clone();
        config.config_path = path;
        tracing::info!(
            addr = %config.client_addr,
            log_level = config.log_level,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "config payload applied"
        );
        self.set_snapshot(config.clone()).await;
        Ok(config)
    }

    pub async fn parse_raw_json(&self, raw_json: &str) -> Result<Config> {
        let path = self.current.read().await.config_path.clone();
        let mut parsed = Config::from_raw_json(&path, raw_json.to_string())?;
        let log_level_present = serde_json::from_str::<serde_json::Value>(raw_json)
            .ok()
            .and_then(|value| {
                value
                    .as_object()
                    .map(|obj| obj.keys().any(|key| key.eq_ignore_ascii_case("LogLevel")))
            })
            .unwrap_or(false);
        if !log_level_present {
            parsed.log_level = self.current.read().await.log_level;
        }
        Ok(parsed)
    }

    pub async fn persist_raw_json(&self, raw_json: &str) -> Result<()> {
        let path = self.current.read().await.config_path.clone();
        let tmp_path = path.with_extension(unique_name("tmp"));
        tracing::debug!(path = %path.display(), tmp = %tmp_path.display(), "persisting raw config payload");

        tokio::fs::write(&tmp_path, raw_json).await?;
        if let Err(err) = tokio::fs::rename(&tmp_path, &path).await {
            if let Err(remove_err) = tokio::fs::remove_file(&tmp_path).await
                && remove_err.kind() != ErrorKind::NotFound
            {
                tracing::warn!(%remove_err, path = %tmp_path.display(), "failed to cleanup temporary config file after persist failure");
            }
            return Err(err.into());
        }

        Ok(())
    }

    pub async fn set_snapshot(&self, config: Config) {
        *self.current.write().await = config;
    }

    pub async fn set_log_level(&self, level: u32) {
        self.current.write().await.log_level = level;
    }
}

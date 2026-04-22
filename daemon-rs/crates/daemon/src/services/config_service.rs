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

    pub async fn reload(&self) -> Result<Config> {
        let path = self.current.read().await.config_path.clone();
        let raw_json = tokio::fs::read_to_string(&path).await?;
        let config = Config::from_raw_json(&path, raw_json)?;
        *self.current.write().await = config.clone();
        Ok(config)
    }

    pub async fn apply_raw_json(&self, raw_json: &str) -> Result<Config> {
        let path = self.current.read().await.config_path.clone();
        let raw_json = raw_json.to_string();
        let tmp_path = path.with_extension(unique_name("tmp"));

        tokio::fs::write(&tmp_path, &raw_json).await?;
        let mut config = match Config::from_raw_json(&tmp_path, raw_json) {
            Ok(config) => config,
            Err(err) => {
                if let Err(remove_err) = tokio::fs::remove_file(&tmp_path).await
                    && remove_err.kind() != ErrorKind::NotFound
                {
                    tracing::warn!(%remove_err, path = %tmp_path.display(), "failed to cleanup temporary config file after parse failure");
                }
                return Err(err);
            }
        };

        tokio::fs::rename(&tmp_path, &path).await?;
        config.config_path = path;
        *self.current.write().await = config.clone();
        Ok(config)
    }

    pub async fn set_log_level(&self, level: u32) {
        self.current.write().await.log_level = level;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::config::Config;
    use crate::utils::test_support::TestDir;

    use super::ConfigService;

    #[tokio::test]
    async fn apply_raw_json_updates_runtime_snapshot() {
        let dir = TestDir::new("opensnitch-config-service-test");
        let config_path = dir.path.join("default-config.json");
        fs::write(&config_path, "{}").expect("write initial config");

        let mut base = Config::default();
        base.config_path = config_path.clone();
        let service = ConfigService::new(base);

        let updated = service
            .apply_raw_json(r#"{"LogLevel":7,"Server":{"Address":"http://127.0.0.1:50052"}}"#)
            .await
            .expect("apply raw json");

        assert_eq!(updated.log_level, 7);
        assert_eq!(updated.client_addr, "http://127.0.0.1:50052");

        let snapshot = service.snapshot().await;
        assert_eq!(snapshot.log_level, 7);
        assert_eq!(snapshot.client_addr, "http://127.0.0.1:50052");
    }

    #[tokio::test]
    async fn apply_raw_json_invalid_proc_monitor_falls_back_to_proc() {
        let dir = TestDir::new("opensnitch-config-service-proc-fallback");
        let config_path = dir.path.join("default-config.json");
        fs::write(&config_path, "{}").expect("write initial config");

        let mut base = Config::default();
        base.config_path = config_path.clone();
        let service = ConfigService::new(base);

        let updated = service
            .apply_raw_json(
                r#"{"LogLevel":2,"ProcMonitorMethod":"invalid-monitor","Server":{"Address":"http://127.0.0.1:50053"}}"#,
            )
            .await
            .expect("apply raw json");

        assert!(matches!(updated.proc_monitor_method, crate::config::ProcMonitorMethod::Proc));
        let snapshot = service.snapshot().await;
        assert!(matches!(snapshot.proc_monitor_method, crate::config::ProcMonitorMethod::Proc));
        assert_eq!(snapshot.client_addr, "http://127.0.0.1:50053");
    }

    #[tokio::test]
    async fn apply_raw_json_invalid_payload_does_not_mutate_snapshot() {
        let dir = TestDir::new("opensnitch-config-service-invalid-json");
        let config_path = dir.path.join("default-config.json");
        fs::write(&config_path, "{}").expect("write initial config");

        let mut base = Config::default();
        base.config_path = config_path.clone();
        let base_addr = base.client_addr.clone();
        let service = ConfigService::new(base);

        let err = service
            .apply_raw_json(r#"{"Server":{"Address":"http://127.0.0.1:50054"}"#)
            .await
            .expect_err("invalid payload should fail");
        assert!(!err.to_string().is_empty());

        let snapshot = service.snapshot().await;
        assert_eq!(snapshot.client_addr, base_addr);
    }
}

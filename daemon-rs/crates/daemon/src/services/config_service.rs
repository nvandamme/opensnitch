use std::{fs, sync::Arc};

use anyhow::Result;
use tokio::sync::RwLock;

use crate::config::Config;

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
        let config = Config::load_from_path(&path)?;
        *self.current.write().await = config.clone();
        Ok(config)
    }

    pub async fn apply_raw_json(&self, raw_json: &str) -> Result<Config> {
        let path = self.current.read().await.config_path.clone();
        fs::write(&path, raw_json)?;
        let config = Config::load_from_path(&path)?;
        *self.current.write().await = config.clone();
        Ok(config)
    }
}

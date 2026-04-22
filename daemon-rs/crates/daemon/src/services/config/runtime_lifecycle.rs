use anyhow::Result;

use super::config::ConfigService;
use crate::config::Config;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

impl ConfigService {
    /// Canonical runtime reload hook for config-backed state.
    #[allow(dead_code)]
    pub(crate) async fn reload_runtime(&self) -> Result<Config> {
        self.reload().await
    }
}

#[async_trait::async_trait]
impl ServiceFactory for ConfigService {
    type FactoryInput = Config;

    async fn init(input: Self::FactoryInput) -> Result<Self> {
        Ok(Self::new(input))
    }
}

#[async_trait::async_trait]
impl ServiceRuntimeControl for ConfigService {
    type ReloadInput = Config;

    async fn reload(&mut self, input: Self::ReloadInput) -> Result<()> {
        self.set_snapshot(input).await;
        Ok(())
    }
}

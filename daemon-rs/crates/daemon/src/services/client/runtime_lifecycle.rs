use anyhow::Result;

use super::client::ClientService;
use crate::config::Config;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

impl ClientService {
    /// Rebuild the client transport/runtime from the latest config snapshot.
    #[allow(dead_code)]
    pub(crate) async fn reload_runtime_transport(&mut self, config: &Config) -> Result<()> {
        *self = Self::connect_with_config(config).await?;
        Ok(())
    }

    /// Refresh session-derived defaults after a config reload.
    #[allow(dead_code)]
    pub(crate) fn reload_runtime_defaults(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
    ) {
        if !self.is_connected() {
            self.set_connected_default_action(disconnected_default_action);
        }
    }
}

#[async_trait::async_trait]
impl ServiceFactory for ClientService {
    type FactoryInput = Config;

    async fn init(input: Self::FactoryInput) -> Result<Self> {
        Self::connect_with_config(&input).await
    }
}

#[async_trait::async_trait]
impl ServiceRuntimeControl for ClientService {
    type ReloadInput = Config;

    async fn reload(&mut self, input: Self::ReloadInput) -> Result<()> {
        self.reload_runtime_defaults(input.default_action);
        Ok(())
    }
}

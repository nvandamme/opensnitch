use anyhow::Result;

use super::client::ClientService;
use crate::config::Config;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

impl ClientService {
    /// Refresh session-derived defaults after a config reload.
    pub(crate) fn reload_runtime_defaults(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
    ) {
        if !self.is_connected() {
            self.set_connected_default_action(disconnected_default_action);
        }
    }
}

impl ServiceFactory for ClientService {
    type FactoryInput = Config;

    async fn init(input: Self::FactoryInput) -> Result<Self> {
        Self::connect_with_config(&input).await
    }
}

impl ServiceRuntimeControl for ClientService {
    type ReloadInput = Config;

    async fn reload(&mut self, input: Self::ReloadInput) -> Result<()> {
        self.reload_runtime_defaults(input.default_action);
        Ok(())
    }
}

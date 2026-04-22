use anyhow::Result;

use super::rule::RuleService;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

impl RuleService {
    /// Canonical runtime reload hook for active rules snapshot/caches.
    #[allow(dead_code)]
    pub(crate) async fn reload_runtime_snapshot(&self) -> Result<usize> {
        self.reload().await
    }
}

#[async_trait::async_trait]
impl ServiceFactory for RuleService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> Result<Self> {
        Ok(Self::default())
    }
}

#[async_trait::async_trait]
impl ServiceRuntimeControl for RuleService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> Result<()> {
        let _ = RuleService::reload(self).await?;
        Ok(())
    }
}

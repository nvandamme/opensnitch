use anyhow::Result;

use super::rule::RuleService;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

impl RuleService {}

impl ServiceFactory for RuleService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> Result<Self> {
        Ok(Self::default())
    }
}

impl ServiceRuntimeControl for RuleService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> Result<()> {
        let _ = RuleService::reload(self).await?;
        Ok(())
    }
}

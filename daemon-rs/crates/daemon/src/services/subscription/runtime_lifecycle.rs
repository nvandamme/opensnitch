use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};
use anyhow::Result;

#[cfg(not(feature = "subscriptions"))]
use super::disabled::SubscriptionService;
#[cfg(feature = "subscriptions")]
use super::subscription::SubscriptionService;

#[cfg(feature = "subscriptions")]
impl SubscriptionService {
    /// Canonical runtime reload hook for subscription runtime state/layout.
    #[allow(dead_code)]
    pub(crate) async fn reload_runtime(&self) -> Result<()> {
        self.sync_layout().await?;
        self.flush_storage_best_effort().await;
        Ok(())
    }
}

#[cfg(feature = "subscriptions")]
impl ServiceFactory for SubscriptionService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> Result<Self> {
        Ok(Self::with_system_defaults())
    }
}

#[cfg(feature = "subscriptions")]
impl ServiceRuntimeControl for SubscriptionService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> Result<()> {
        self.reload_runtime().await
    }
}

#[cfg(not(feature = "subscriptions"))]
impl SubscriptionService {
    #[allow(dead_code)]
    pub(crate) async fn reload_runtime(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(not(feature = "subscriptions"))]
impl ServiceFactory for SubscriptionService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> Result<Self> {
        Ok(Self::with_system_defaults())
    }
}

#[cfg(not(feature = "subscriptions"))]
impl ServiceRuntimeControl for SubscriptionService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> Result<()> {
        self.reload_runtime().await
    }
}

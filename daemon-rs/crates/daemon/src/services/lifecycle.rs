use std::time::Duration;
use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{broadcast, watch};

pub(crate) use crate::services::lifecycle_contract::{
    ServiceEvent, ServiceMonitorStats, ServiceState, ServiceStatus,
};

#[derive(Debug)]
pub(crate) struct StatusSubscription {
    receiver: watch::Receiver<ServiceStatus>,
    active_counter: Arc<AtomicUsize>,
}

impl StatusSubscription {
    pub(crate) fn new(
        receiver: watch::Receiver<ServiceStatus>,
        active_counter: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            receiver,
            active_counter,
        }
    }
}

impl Deref for StatusSubscription {
    type Target = watch::Receiver<ServiceStatus>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl DerefMut for StatusSubscription {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}

impl Drop for StatusSubscription {
    fn drop(&mut self) {
        self.active_counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(crate) struct EventSubscription {
    receiver: broadcast::Receiver<ServiceEvent>,
    active_counter: Arc<AtomicUsize>,
}

impl EventSubscription {
    pub(crate) fn new(
        receiver: broadcast::Receiver<ServiceEvent>,
        active_counter: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            receiver,
            active_counter,
        }
    }
}

impl Deref for EventSubscription {
    type Target = broadcast::Receiver<ServiceEvent>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl DerefMut for EventSubscription {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.active_counter.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn subscribe_status_with_counter(
    status_tx: &watch::Sender<ServiceStatus>,
    status_subscribers: &Arc<AtomicUsize>,
) -> StatusSubscription {
    status_subscribers.fetch_add(1, Ordering::Relaxed);
    StatusSubscription::new(status_tx.subscribe(), status_subscribers.clone())
}

pub(crate) fn subscribe_events_with_counter(
    event_tx: &broadcast::Sender<ServiceEvent>,
    event_subscribers: &Arc<AtomicUsize>,
) -> EventSubscription {
    event_subscribers.fetch_add(1, Ordering::Relaxed);
    EventSubscription::new(event_tx.subscribe(), event_subscribers.clone())
}

pub(crate) fn monitor_stats_from_counters(
    status_subscribers: &AtomicUsize,
    event_subscribers: &AtomicUsize,
) -> ServiceMonitorStats {
    ServiceMonitorStats {
        status_subscribers: status_subscribers.load(Ordering::Relaxed),
        event_subscribers: event_subscribers.load(Ordering::Relaxed),
    }
}
// Shared lifecycle trait surface is retained for cross-service API stability.
#[allow(dead_code)]
pub(crate) trait ServiceFactory: Sized {
    type FactoryInput: Send;

    async fn init(input: Self::FactoryInput) -> anyhow::Result<Self>;
}
// Shared lifecycle trait surface is retained for cross-service API stability.
#[allow(dead_code)]
pub(crate) trait ServiceRuntimeControl {
    type ReloadInput: Send;

    async fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn reload(&mut self, input: Self::ReloadInput) -> anyhow::Result<()>;
}
// Shared lifecycle trait surface is retained for cross-service API stability.
#[allow(dead_code)]
pub(crate) trait ServiceLifecycle {
    async fn init(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn reload(&mut self) -> anyhow::Result<()> {
        self.stop().await?;
        self.start().await
    }
    async fn quiesce(&mut self) -> anyhow::Result<()> {
        self.pause().await
    }
    async fn drain(&mut self, _timeout: Duration) -> anyhow::Result<()> {
        Ok(())
    }
    async fn health_check(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn status(&self) -> ServiceStatus {
        ServiceStatus::default()
    }
    async fn reset(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        anyhow::bail!("service does not expose status subscription")
    }

    fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        anyhow::bail!("service does not expose event subscription")
    }

    fn monitor_stats(&self) -> ServiceMonitorStats {
        ServiceMonitorStats::default()
    }
}

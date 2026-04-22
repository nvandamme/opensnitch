use std::sync::{
    Arc,
    atomic::AtomicUsize,
};

use tokio::sync::{broadcast, watch};

use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceFactory, ServiceLifecycle, ServiceMonitorStats,
    ServiceRuntimeControl, ServiceState, ServiceStatus, StatusSubscription,
    monitor_stats_from_counters,
    subscribe_events_with_counter, subscribe_status_with_counter,
};
use crate::services::dns::DnsService;

#[derive(Clone)]
pub(crate) struct DnsLifecycle {
    status_tx: watch::Sender<ServiceStatus>,
    event_tx: broadcast::Sender<ServiceEvent>,
    status_subscribers: Arc<AtomicUsize>,
    event_subscribers: Arc<AtomicUsize>,
    lifecycle_state: Arc<std::sync::Mutex<ServiceState>>,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl Default for DnsLifecycle {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(64);
        Self {
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: Arc::new(std::sync::Mutex::new(ServiceState::Uninitialized)),
            last_error: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl DnsLifecycle {
    pub(crate) fn mark_running(&self) {
        self.clear_error_and_transition(ServiceState::Running);
    }

    fn clear_error_and_transition(&self, to: ServiceState) {
        self.set_error(None);
        self.transition_state(to);
    }

    fn current_status(&self) -> ServiceStatus {
        ServiceStatus {
            state: self
                .lifecycle_state
                .lock()
                .map(|state| *state)
                .unwrap_or(ServiceState::Degraded),
            last_error: self
                .last_error
                .lock()
                .map(|err| err.clone())
                .unwrap_or_else(|_| Some("dns lifecycle state unavailable".to_string())),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_tx.send(self.current_status());
    }

    fn transition_state(&self, to: ServiceState) {
        let from = self
            .lifecycle_state
            .lock()
            .map(|mut state| {
                let from = *state;
                *state = to;
                from
            })
            .unwrap_or(ServiceState::Degraded);

        self.publish_status();
        let _ = self.event_tx.send(ServiceEvent::StateChanged {
            from,
            to,
            last_error: self.last_error.lock().ok().and_then(|err| err.clone()),
        });
    }

    fn set_error(&self, error: Option<String>) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = error;
        }
        self.publish_status();
    }
}

#[async_trait::async_trait]
impl ServiceLifecycle for DnsLifecycle {
    async fn init(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Stopped);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Running);
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Paused);
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Running);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Stopped);
        Ok(())
    }

    fn status(&self) -> ServiceStatus {
        self.current_status()
    }

    fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        Ok(subscribe_status_with_counter(
            &self.status_tx,
            &self.status_subscribers,
        ))
    }

    fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        Ok(subscribe_events_with_counter(
            &self.event_tx,
            &self.event_subscribers,
        ))
    }

    fn monitor_stats(&self) -> ServiceMonitorStats {
        monitor_stats_from_counters(&self.status_subscribers, &self.event_subscribers)
    }
}

#[async_trait::async_trait]
impl ServiceFactory for DnsService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> anyhow::Result<Self> {
        Ok(Self::default())
    }
}

#[async_trait::async_trait]
impl ServiceRuntimeControl for DnsService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> anyhow::Result<()> {
        self.ip_lookup.clear();
        self.alias_lookup.clear();
        Ok(())
    }
}

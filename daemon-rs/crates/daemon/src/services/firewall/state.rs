use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::{broadcast, watch};

use crate::{
    services::lifecycle::{
        EventSubscription, ServiceEvent, ServiceLifecycle, ServiceMonitorStats, ServiceState,
        ServiceStatus, StatusSubscription,
    },
};

pub(crate) use crate::models::firewall_runtime::FirewallRuntime;

#[derive(Clone)]
pub(crate) struct FirewallRuntimeState {
    snapshot_tx: watch::Sender<Arc<FirewallRuntime>>,
    snapshot_rx: watch::Receiver<Arc<FirewallRuntime>>,
    status_tx: watch::Sender<ServiceStatus>,
    event_tx: broadcast::Sender<ServiceEvent>,
    status_subscribers: Arc<AtomicUsize>,
    event_subscribers: Arc<AtomicUsize>,
    lifecycle_state: Arc<std::sync::Mutex<ServiceState>>,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl FirewallRuntimeState {
    pub(crate) fn new(initial_runtime: FirewallRuntime) -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(initial_runtime));
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Stopped,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(64);
        Self {
            snapshot_tx,
            snapshot_rx,
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: Arc::new(std::sync::Mutex::new(ServiceState::Stopped)),
            last_error: Arc::new(std::sync::Mutex::new(None)),
        }
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
                .unwrap_or_else(|_| Some("firewall runtime state unavailable".to_string())),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_subscribers.load(Ordering::Relaxed);
        let _ = self.event_subscribers.load(Ordering::Relaxed);
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

    pub(crate) fn snapshot(&self) -> Arc<FirewallRuntime> {
        self.snapshot_rx.borrow().clone()
    }

    pub(crate) fn publish_snapshot(&self, next: FirewallRuntime) {
        self.snapshot_tx.send_replace(Arc::new(next));
        self.set_error(None);
        self.transition_state(ServiceState::Running);
    }

    pub(crate) fn build_and_publish<F>(&self, build: F) -> Arc<FirewallRuntime>
    where
        F: FnOnce(&FirewallRuntime) -> FirewallRuntime,
    {
        let current = self.snapshot();
        let next = Arc::new(build(current.as_ref()));
        self.snapshot_tx.send_replace(next.clone());
        self.set_error(None);
        self.transition_state(ServiceState::Running);
        next
    }
}

#[tonic::async_trait]
impl ServiceLifecycle for FirewallRuntimeState {
    async fn init(&mut self) -> anyhow::Result<()> {
        self.set_error(None);
        self.transition_state(ServiceState::Stopped);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.set_error(None);
        self.transition_state(ServiceState::Running);
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        self.set_error(None);
        self.transition_state(ServiceState::Paused);
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        self.set_error(None);
        self.transition_state(ServiceState::Running);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.set_error(None);
        self.transition_state(ServiceState::Stopped);
        Ok(())
    }

    fn status(&self) -> ServiceStatus {
        self.current_status()
    }

    fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        self.status_subscribers.fetch_add(1, Ordering::Relaxed);
        Ok(StatusSubscription::new(
            self.status_tx.subscribe(),
            self.status_subscribers.clone(),
        ))
    }

    fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        self.event_subscribers.fetch_add(1, Ordering::Relaxed);
        Ok(EventSubscription::new(
            self.event_tx.subscribe(),
            self.event_subscribers.clone(),
        ))
    }

    fn monitor_stats(&self) -> ServiceMonitorStats {
        ServiceMonitorStats {
            status_subscribers: self.status_subscribers.load(Ordering::Relaxed),
            event_subscribers: self.event_subscribers.load(Ordering::Relaxed),
        }
    }
}

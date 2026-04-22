use crate::models::{
    connection_context::ConnectionContext,
    connection_worker_state::{ConnectionWorkerState, ConnectionWorkerKind},
    connection_state::ConnectionAttempt,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::bus::Bus;
use crate::services::ebpf::EbpfObjectAvailability;
use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceLifecycle, ServiceMonitorStats, ServiceState,
    ServiceStatus, StatusSubscription,
};
use crate::services::{dns::DnsService, process::ProcessService};
use crate::tunables::RuntimeTunables;
use crate::workers::{
    connection::ebpf_worker::EbpfConnWorkerControl, runtime::control::WorkerControl,
};

pub struct ConnectionRuntime {
    pub(super) state: Mutex<ConnectionWorkerState>,
    pub(super) status_tx: watch::Sender<ServiceStatus>,
    pub(super) event_tx: broadcast::Sender<ServiceEvent>,
    pub(super) status_subscribers: Arc<AtomicUsize>,
    pub(super) event_subscribers: Arc<AtomicUsize>,
    pub(super) lifecycle_state: Mutex<ServiceState>,
    pub(super) last_error: Mutex<Option<String>>,
}

impl Default for ConnectionRuntime {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(64);

        Self {
            state: Mutex::new(ConnectionWorkerState::default()),
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: Mutex::new(ServiceState::Uninitialized),
            last_error: Mutex::new(None),
        }
    }
}

impl ConnectionRuntime {
    pub(super) fn current_status(&self) -> ServiceStatus {
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
                .unwrap_or_else(|_| Some("connection intent state unavailable".to_string())),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_subscribers.load(Ordering::Relaxed);
        let _ = self.event_subscribers.load(Ordering::Relaxed);
        let _ = self.status_tx.send(self.current_status());
    }

    pub(super) fn transition_state(&self, to: ServiceState) {
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

    pub(super) fn set_error(&self, error: Option<String>) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = error;
        }
        self.publish_status();
    }

    pub fn init_workers(
        &self,
        bus: Bus,
        daemon_shutdown: CancellationToken,
        tunables: RuntimeTunables,
        ebpf_availability: EbpfObjectAvailability,
    ) -> Vec<Box<dyn WorkerControl>> {
        if ebpf_availability.conn_available {
            if let Ok(mut st) = self.state.lock() {
                st.worker_kind = ConnectionWorkerKind::Ebpf;
            }
            self.set_error(None);
            self.transition_state(ServiceState::Running);
            return vec![Box::new(EbpfConnWorkerControl::new(
                bus,
                daemon_shutdown,
                tunables,
            ))];
        }

        if let Ok(mut st) = self.state.lock() {
            st.worker_kind = ConnectionWorkerKind::Fallback;
        }
        self.set_error(None);
        self.transition_state(ServiceState::Running);
        Vec::new()
    }

    pub fn snapshot(&self) -> ConnectionWorkerState {
        self.state.lock().map(|state| *state).unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct ConnectionService {
    pub(super) process: ProcessService,
    pub(super) dns: DnsService,
    intent: Arc<ConnectionRuntime>,
}

impl ConnectionService {
    pub fn new(process: ProcessService, dns: DnsService) -> Self {
        Self {
            process,
            dns,
            intent: Arc::new(ConnectionRuntime::default()),
        }
    }

    pub fn init_workers(
        &self,
        bus: Bus,
        daemon_shutdown: CancellationToken,
        tunables: RuntimeTunables,
        ebpf_availability: EbpfObjectAvailability,
    ) -> Vec<Box<dyn WorkerControl>> {
        self.intent
            .init_workers(bus, daemon_shutdown, tunables, ebpf_availability)
    }

    pub fn worker_state(&self) -> ConnectionWorkerState {
        self.intent.snapshot()
    }

    pub fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        ServiceLifecycle::subscribe_status(self.intent.as_ref())
    }

    pub fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        ServiceLifecycle::subscribe_events(self.intent.as_ref())
    }

    pub fn status(&self) -> ServiceStatus {
        ServiceLifecycle::status(self.intent.as_ref())
    }

    pub fn monitor_stats(&self) -> ServiceMonitorStats {
        ServiceLifecycle::monitor_stats(self.intent.as_ref())
    }

    pub async fn resolve(&self, attempt: ConnectionAttempt) -> ConnectionContext {
        self.resolve_context(attempt).await
    }
}

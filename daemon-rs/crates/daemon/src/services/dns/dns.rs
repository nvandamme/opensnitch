use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::bus::Bus;
use crate::models::dns_worker_state::{DnsWorkerState, DnsWorkerKind};
use crate::services::ebpf::EbpfObjectAvailability;
use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceLifecycle, ServiceMonitorStats, ServiceState,
    ServiceStatus, StatusSubscription,
};
use crate::tunables::RuntimeTunables;
use crate::utils::lru_cache::DualLayerLruMap;
use crate::workers::{
    dns::{dns_worker::DnsWorkerControl, ebpf_worker::EbpfDnsWorkerControl},
    runtime::control::WorkerControl,
};

const fn default_dns_cache_capacity() -> usize {
    if cfg!(test) {
        8_192
    } else {
        4_000_000
    }
}

const DEFAULT_DNS_CACHE_CAPACITY: usize = default_dns_cache_capacity();
pub(super) static DNS_CACHE_CAPACITY: AtomicUsize = AtomicUsize::new(DEFAULT_DNS_CACHE_CAPACITY);

pub struct DnsRuntime {
    pub(super) state: Mutex<DnsWorkerState>,
    pub(super) status_tx: watch::Sender<ServiceStatus>,
    pub(super) event_tx: broadcast::Sender<ServiceEvent>,
    pub(super) status_subscribers: Arc<AtomicUsize>,
    pub(super) event_subscribers: Arc<AtomicUsize>,
    pub(super) lifecycle_state: Mutex<ServiceState>,
    pub(super) last_error: Mutex<Option<String>>,
}

impl Default for DnsRuntime {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(64);

        Self {
            state: Mutex::new(DnsWorkerState::default()),
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: Mutex::new(ServiceState::Uninitialized),
            last_error: Mutex::new(None),
        }
    }
}

impl DnsRuntime {
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
                .unwrap_or_else(|_| Some("dns intent state unavailable".to_string())),
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
        if ebpf_availability.dns_available {
            if let Ok(mut st) = self.state.lock() {
                st.worker_kind = DnsWorkerKind::Ebpf;
            }
            self.set_error(None);
            self.transition_state(ServiceState::Running);
            return vec![Box::new(EbpfDnsWorkerControl::new(
                bus,
                daemon_shutdown,
                tunables,
            ))];
        }

        if let Ok(mut st) = self.state.lock() {
            st.worker_kind = DnsWorkerKind::Fallback;
        }
        self.set_error(None);
        self.transition_state(ServiceState::Running);
        vec![Box::new(DnsWorkerControl::new(bus, daemon_shutdown))]
    }

    pub fn snapshot(&self) -> DnsWorkerState {
        self.state.lock().map(|state| *state).unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct DnsService {
    pub(super) ip_lookup: Arc<DualLayerLruMap<IpAddr, Arc<str>>>,
    pub(super) alias_lookup: Arc<DualLayerLruMap<Arc<str>, Arc<str>>>,
    intent: Arc<DnsRuntime>,
}

impl Default for DnsService {
    fn default() -> Self {
        let capacity = DNS_CACHE_CAPACITY.load(Ordering::Relaxed).max(1);
        Self {
            ip_lookup: Arc::new(DualLayerLruMap::new(capacity)),
            alias_lookup: Arc::new(DualLayerLruMap::new(capacity)),
            intent: Arc::new(DnsRuntime::default()),
        }
    }
}

#[derive(Default)]
pub(crate) struct DnsEbpfEventDeduper {
    pub(super) recent_events: HashMap<(String, String), Instant>,
}

impl DnsService {
    #[allow(dead_code)]
    pub(crate) const EBPF_DNS_EVENT_LEN: usize = opensnitch_ebpf_common::dns::DnsEvent::LEN;

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

    pub fn worker_state(&self) -> DnsWorkerState {
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
}

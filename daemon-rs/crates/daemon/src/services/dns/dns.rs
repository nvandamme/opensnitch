use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::bus::Bus;
use crate::models::dns_worker_state::{DnsWorkerKind, DnsWorkerState};
use crate::services::ebpf::EbpfObjectAvailability;
use crate::services::lifecycle::{
    EventSubscription, ServiceLifecycle, ServiceMonitorStats, ServiceStatus, StatusSubscription,
};
use crate::tunables::RuntimeTunables;
use crate::utils::lru_cache::DualLayerLruMap;
use crate::workers::{
    dns::{dns_worker::DnsWorkerControl, ebpf_worker::EbpfDnsWorkerControl},
    runtime::control::WorkerControl,
};

use super::runtime_lifecycle::DnsLifecycle;

const fn default_dns_cache_capacity() -> usize {
    if cfg!(test) { 8_192 } else { 4_000_000 }
}

const DEFAULT_DNS_CACHE_CAPACITY: usize = default_dns_cache_capacity();
pub(super) static DNS_CACHE_CAPACITY: AtomicUsize = AtomicUsize::new(DEFAULT_DNS_CACHE_CAPACITY);

pub struct DnsRuntime {
    pub(super) state: Mutex<DnsWorkerState>,
    pub(super) monitor_state: Arc<AtomicU8>,
}

impl Default for DnsRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(DnsWorkerState::default()),
            monitor_state: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl DnsRuntime {
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
            return vec![Box::new(EbpfDnsWorkerControl::new(
                bus,
                daemon_shutdown,
                tunables,
            ))];
        }

        if let Ok(mut st) = self.state.lock() {
            st.worker_kind = DnsWorkerKind::Fallback;
        }
        vec![Box::new(DnsWorkerControl::new(
            bus,
            daemon_shutdown,
            self.monitor_state.clone(),
        ))]
    }

    pub fn snapshot(&self) -> DnsWorkerState {
        self.state.lock().map(|state| *state).unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct DnsService {
    pub(super) ip_lookup: Arc<DualLayerLruMap<IpAddr, Arc<str>>>,
    pub(super) alias_lookup: Arc<DualLayerLruMap<Arc<str>, Arc<str>>>,
    runtime: Arc<DnsRuntime>,
    lifecycle: DnsLifecycle,
}

impl Default for DnsService {
    fn default() -> Self {
        let capacity = DNS_CACHE_CAPACITY.load(Ordering::Relaxed).max(1);
        Self {
            ip_lookup: Arc::new(DualLayerLruMap::new(capacity)),
            alias_lookup: Arc::new(DualLayerLruMap::new(capacity)),
            runtime: Arc::new(DnsRuntime::default()),
            lifecycle: DnsLifecycle::default(),
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
        let workers = self
            .runtime
            .init_workers(bus, daemon_shutdown, tunables, ebpf_availability);
        self.lifecycle.mark_running();
        workers
    }

    pub(crate) fn dns_monitor_state_label(&self) -> &'static str {
        crate::workers::dns::dns_worker::decode_dns_monitor_state_label(
            self.runtime.monitor_state.load(Ordering::Relaxed),
        )
    }

    pub fn worker_state(&self) -> DnsWorkerState {
        self.runtime.snapshot()
    }

    pub fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        ServiceLifecycle::subscribe_status(&self.lifecycle)
    }

    pub fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        ServiceLifecycle::subscribe_events(&self.lifecycle)
    }

    pub fn status(&self) -> ServiceStatus {
        ServiceLifecycle::status(&self.lifecycle)
    }

    pub fn monitor_stats(&self) -> ServiceMonitorStats {
        ServiceLifecycle::monitor_stats(&self.lifecycle)
    }
}

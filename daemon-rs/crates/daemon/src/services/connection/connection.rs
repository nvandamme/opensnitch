use crate::models::{
    connection_context::ConnectionContext,
    connection_worker_state::{ConnectionWorkerState, ConnectionWorkerKind},
    connection_state::ConnectionAttempt,
};
use std::sync::{
    Arc, Mutex,
};
use tokio_util::sync::CancellationToken;

use crate::bus::Bus;
use crate::services::ebpf::EbpfObjectAvailability;
use crate::services::lifecycle::{
    EventSubscription, ServiceLifecycle, ServiceMonitorStats, ServiceStatus, StatusSubscription,
};
use crate::services::{dns::DnsService, process::ProcessService};
use crate::tunables::RuntimeTunables;
use crate::workers::{
    connection::ebpf_worker::EbpfConnWorkerControl, runtime::control::WorkerControl,
};

use super::runtime_lifecycle::ConnectionLifecycle;
use super::ebpf::BpfMapIdCache;

pub struct ConnectionRuntime {
    pub(super) state: Mutex<ConnectionWorkerState>,
    pub(super) bpf_map_ids: Mutex<BpfMapIdCache>,
}

impl Default for ConnectionRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(ConnectionWorkerState::default()),
            bpf_map_ids: Mutex::new(BpfMapIdCache::default()),
        }
    }
}

impl ConnectionRuntime {
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
            return vec![Box::new(EbpfConnWorkerControl::new(
                bus,
                daemon_shutdown,
                tunables,
            ))];
        }

        if let Ok(mut st) = self.state.lock() {
            st.worker_kind = ConnectionWorkerKind::Fallback;
        }
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
    runtime: Arc<ConnectionRuntime>,
    lifecycle: ConnectionLifecycle,
}

impl ConnectionService {
    pub(super) fn bpf_map_ids(&self) -> &Mutex<BpfMapIdCache> {
        &self.runtime.bpf_map_ids
    }

    pub fn new(process: ProcessService, dns: DnsService) -> Self {
        Self {
            process,
            dns,
            runtime: Arc::new(ConnectionRuntime::default()),
            lifecycle: ConnectionLifecycle::default(),
        }
    }

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

    pub fn worker_state(&self) -> ConnectionWorkerState {
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

    pub async fn resolve(&self, attempt: ConnectionAttempt) -> ConnectionContext {
        self.resolve_context(attempt).await
    }
}

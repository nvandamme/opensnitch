use crate::models::{
    connection_context::ConnectionContext,
    connection_state::ConnectionAttempt,
    connection_worker_state::{ConnectionWorkerKind, ConnectionWorkerState},
};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

pub struct ConnectionRuntime {
    pub(super) state: Mutex<ConnectionWorkerState>,
    /// Lock-free snapshot of eBPF map name → kernel id, refreshed every 30 s by a
    /// background task spawned in [`ConnectionRuntime::init_workers`].  The hot
    /// connection path reads atomically via ArcSwap — no lock on the read side.
    pub(super) bpf_map_snapshot: Arc<ArcSwap<HashMap<String, u32>>>,
}

impl Default for ConnectionRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(ConnectionWorkerState::default()),
            bpf_map_snapshot: Arc::new(ArcSwap::from_pointee(HashMap::new())),
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
        // Spawn background eBPF map-id refresh task.  Fires immediately on first tick
        // (tokio interval tick 0 is instant) and then every 30 s, replacing the snapshot
        // atomically so the hot connection path never blocks on a refresh.
        {
            let snapshot = Arc::clone(&self.bpf_map_snapshot);
            let ct = daemon_shutdown.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let new_map =
                                tokio::task::spawn_blocking(super::ebpf::list_bpf_maps)
                                    .await
                                    .unwrap_or_default();
                            snapshot.store(Arc::new(new_map));
                        }
                        _ = ct.cancelled() => break,
                    }
                }
            });
        }

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
    pub(super) fn bpf_map_snapshot(&self) -> &Arc<ArcSwap<HashMap<String, u32>>> {
        &self.runtime.bpf_map_snapshot
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

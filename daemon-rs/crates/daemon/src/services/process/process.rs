use std::sync::{Arc, Mutex, atomic::AtomicUsize};

use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::bus::Bus;
use crate::config::ProcMonitorMethod;
use crate::models::process_worker_state::ProcessWorkerState;
use crate::services::ebpf::EbpfObjectAvailability;
use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceLifecycle, ServiceMonitorStats, ServiceState,
    ServiceStatus, StatusSubscription,
};
use crate::tunables::RuntimeTunables;
use crate::workers::{
    process::{
        audit_worker::AuditWorkerControl, ebpf_worker::EbpfProcWorkerControl,
        netlink_worker::NetlinkProcWorkerControl,
    },
    runtime::control::{ThreadWorkerControl, WorkerControl},
};

use super::cache::ProcessCache;

pub struct ProcessRuntime {
    pub(super) state: Mutex<ProcessWorkerState>,
    pub(super) status_tx: watch::Sender<ServiceStatus>,
    pub(super) event_tx: broadcast::Sender<ServiceEvent>,
    pub(super) status_subscribers: Arc<AtomicUsize>,
    pub(super) event_subscribers: Arc<AtomicUsize>,
    pub(super) lifecycle_state: Mutex<ServiceState>,
    pub(super) last_error: Mutex<Option<String>>,
}

impl Default for ProcessRuntime {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(64);

        Self {
            state: Mutex::new(ProcessWorkerState::default()),
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: Mutex::new(ServiceState::Uninitialized),
            last_error: Mutex::new(None),
        }
    }
}

impl ProcessRuntime {
    pub fn preferred_monitor_method(
        &self,
        requested_method: ProcMonitorMethod,
        ebpf_availability: EbpfObjectAvailability,
    ) -> ProcMonitorMethod {
        match requested_method {
            ProcMonitorMethod::Ebpf if ebpf_availability.proc_available => ProcMonitorMethod::Ebpf,
            ProcMonitorMethod::Ebpf => ProcMonitorMethod::Proc,
            _ => requested_method,
        }
    }

    pub fn init_workers(
        &self,
        method: ProcMonitorMethod,
        bus: Bus,
        shutdown: CancellationToken,
        tunables: RuntimeTunables,
        audit_socket_path: std::path::PathBuf,
        ebpf_availability: EbpfObjectAvailability,
    ) -> Vec<Box<dyn WorkerControl>> {
        let handles = match method {
            ProcMonitorMethod::Proc => vec![ThreadWorkerControl::boxed(
                "proc-netlink",
                NetlinkProcWorkerControl::spawn(bus.clone(), shutdown),
            )],
            ProcMonitorMethod::Ebpf => {
                if ebpf_availability.proc_available {
                    vec![
                        Box::new(EbpfProcWorkerControl::new(bus, shutdown, tunables))
                            as Box<dyn WorkerControl>,
                    ]
                } else {
                    vec![ThreadWorkerControl::boxed(
                        "proc-netlink",
                        NetlinkProcWorkerControl::spawn(bus, shutdown),
                    )]
                }
            }
            ProcMonitorMethod::Audit => vec![
                ThreadWorkerControl::boxed(
                    "proc-audit",
                    AuditWorkerControl::spawn(bus.clone(), audit_socket_path, shutdown.clone()),
                ),
                ThreadWorkerControl::boxed(
                    "proc-netlink",
                    NetlinkProcWorkerControl::spawn(bus, shutdown),
                ),
            ],
        };

        if let Ok(mut st) = self.state.lock() {
            st.requested_method = method;
            st.worker_count = handles.len();
            st.ebpf_requested = matches!(method, ProcMonitorMethod::Ebpf);
            st.ebpf_available = ebpf_availability.proc_available;
        }
        self.set_error(None);
        self.transition_state(ServiceState::Running);

        handles
    }
}

#[derive(Clone, Default)]
pub struct ProcessService {
    pub(super) cache: Arc<ProcessCache>,
    intent: Arc<ProcessRuntime>,
}

impl ProcessService {
    pub(crate) const EV_TYPE_EXEC: u64 = 1;
    pub(crate) const EV_TYPE_EXECVEAT: u64 = 2;
    pub(crate) const EV_TYPE_FORK: u64 = 3;
    pub(crate) const EV_TYPE_SCHED_EXIT: u64 = 4;

    pub(crate) const EXEC_HDR_LEN: usize = 26;
    pub(crate) const MAX_PATH_LEN: usize = 4096;
    pub(crate) const MAX_ARGS: usize = 20;
    pub(crate) const MAX_ARG_LEN: usize = 256;
    pub(crate) const TASK_COMM_LEN: usize = 16;
    pub(crate) const EBPF_EXEC_EVENT_LEN: usize = Self::EXEC_HDR_LEN
        + Self::MAX_PATH_LEN
        + (Self::MAX_ARGS * Self::MAX_ARG_LEN)
        + Self::TASK_COMM_LEN;

    pub fn preferred_monitor_method(
        &self,
        requested_method: ProcMonitorMethod,
        ebpf_availability: EbpfObjectAvailability,
    ) -> ProcMonitorMethod {
        self.intent
            .preferred_monitor_method(requested_method, ebpf_availability)
    }

    pub fn init_workers(
        &self,
        method: ProcMonitorMethod,
        bus: Bus,
        shutdown: CancellationToken,
        tunables: RuntimeTunables,
        audit_socket_path: std::path::PathBuf,
        ebpf_availability: EbpfObjectAvailability,
    ) -> Vec<Box<dyn WorkerControl>> {
        self.intent.init_workers(
            method,
            bus,
            shutdown,
            tunables,
            audit_socket_path,
            ebpf_availability,
        )
    }

    pub fn worker_state(&self) -> ProcessWorkerState {
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

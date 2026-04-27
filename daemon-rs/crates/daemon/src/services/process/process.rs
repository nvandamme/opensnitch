use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::bus::Bus;
use crate::config::ProcMonitorMethod;
use crate::models::process::worker_state::ProcessWorkerState;
use crate::services::ebpf::EbpfObjectAvailability;
use crate::services::lifecycle::{
    EventSubscription, ServiceLifecycle, ServiceMonitorStats, ServiceStatus, StatusSubscription,
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
use super::runtime_lifecycle::ProcessLifecycle;

pub struct ProcessRuntime {
    pub(super) state: Mutex<ProcessWorkerState>,
}

impl Default for ProcessRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(ProcessWorkerState::default()),
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

        handles
    }

    pub(super) fn snapshot(&self) -> ProcessWorkerState {
        self.state.lock().map(|state| *state).unwrap_or_default()
    }
}

#[derive(Clone, Default)]
pub struct ProcessService {
    pub(super) cache: Arc<ProcessCache>,
    runtime: Arc<ProcessRuntime>,
    lifecycle: ProcessLifecycle,
}

impl ProcessService {
    // eBPF event layout constants are consumed by native ringbuf parsing paths.
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const EV_TYPE_EXEC: u64 = ebpf_common::process::EV_TYPE_EXEC;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const EV_TYPE_EXECVEAT: u64 = ebpf_common::process::EV_TYPE_EXECVEAT;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const EV_TYPE_FORK: u64 = ebpf_common::process::EV_TYPE_FORK;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const EV_TYPE_SCHED_EXIT: u64 = ebpf_common::process::EV_TYPE_SCHED_EXIT;

    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const EXEC_HDR_LEN: usize = ebpf_common::process::ExecEvent::HDR_LEN;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const MAX_PATH_LEN: usize = ebpf_common::process::MAX_PATH_LEN;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const MAX_ARGS: usize = ebpf_common::process::MAX_ARGS;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const MAX_ARG_LEN: usize = ebpf_common::process::MAX_ARG_LEN;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const TASK_COMM_LEN: usize = ebpf_common::process::TASK_COMM_LEN;
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(crate) const EBPF_EXEC_EVENT_LEN: usize = ebpf_common::process::ExecEvent::LEN;

    pub fn preferred_monitor_method(
        &self,
        requested_method: ProcMonitorMethod,
        ebpf_availability: EbpfObjectAvailability,
    ) -> ProcMonitorMethod {
        self.runtime
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
        let workers = self.runtime.init_workers(
            method,
            bus,
            shutdown,
            tunables,
            audit_socket_path,
            ebpf_availability,
        );
        self.lifecycle.mark_running();
        workers
    }

    pub fn worker_state(&self) -> ProcessWorkerState {
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

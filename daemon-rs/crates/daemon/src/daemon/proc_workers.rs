use std::{future::Future, pin::Pin, time::Duration};

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::Daemon;
use crate::{
    commands::control,
    config::ProcMonitorMethod,
    services::ebpf::EbpfService,
    utils::systemd_notify::{NotifyState, notify},
    workers::runtime::control::{
        WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus, WorkerState,
    },
};

pub(crate) struct ProcWorkersRuntime {
    pub(crate) current_method: ProcMonitorMethod,
    pub(crate) shutdown: CancellationToken,
    pub(crate) handles: Vec<Box<dyn WorkerControl>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProcWorkersSnapshot {
    pub(super) method: ProcMonitorMethod,
    pub(super) state: WorkerState,
    pub(super) configured_handles: usize,
    pub(super) running_handles: usize,
    pub(super) shutdown_requested: bool,
}

#[derive(Clone)]
pub(super) struct ProcWorkersControl {
    pub(super) daemon: Daemon,
}

impl ProcWorkersControl {
    pub(super) fn snapshot(&self) -> ProcWorkersSnapshot {
        self.daemon.proc_workers_snapshot()
    }

    fn start_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Start)
    }

    fn stop_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Stop)
    }

    fn inspect_workers(&self) -> WorkerCommandResult {
        self.daemon.control_proc_workers_sync(WorkerCommand::Probe)
    }
}

impl WorkerControl for ProcWorkersControl {
    fn worker_name(&self) -> &'static str {
        "proc-workers"
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Start => self.start_workers(),
            WorkerCommand::Stop => self.stop_workers(),
            WorkerCommand::Probe => self.inspect_workers(),
        }
    }

    fn state(&self) -> WorkerState {
        self.snapshot().state
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        self.stop();
        WorkerJoinStatus::Stopped
    }
}

impl crate::workers::runtime::control::OneShotWorker for ProcWorkersControl {}

pub(super) struct DaemonProcWorkerReconfigurePort {
    pub(super) daemon: Daemon,
}

impl control::ProcWorkerReconfigurePort for DaemonProcWorkerReconfigurePort {
    fn reconfigure_proc_workers(
        &self,
        method: Option<ProcMonitorMethod>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let daemon = self.daemon.clone();
        Box::pin(async move { daemon.reconfigure_proc_workers(method).await })
    }
}

pub(super) struct DaemonProcWorkerControlPort {
    pub(super) proc_workers: ProcWorkersControl,
}

impl control::ProcWorkerControlPort for DaemonProcWorkerControlPort {
    fn control_proc_workers(
        &self,
        command: WorkerCommand,
    ) -> Pin<Box<dyn Future<Output = WorkerCommandResult> + Send + '_>> {
        let proc_workers = self.proc_workers.clone();
        Box::pin(async move { proc_workers.control(command) })
    }
}

impl Daemon {
    pub(super) fn spawn_proc_worker_handles(
        &self,
        method: ProcMonitorMethod,
        shutdown: CancellationToken,
    ) -> Vec<Box<dyn WorkerControl>> {
        self.inner.process.init_workers(
            method,
            self.inner.bus.clone(),
            shutdown,
            self.inner.tunables,
            self.inner.audit_socket_path.clone(),
            EbpfService::probe_availability(),
        )
    }

    pub(super) fn proc_workers_control(&self) -> ProcWorkersControl {
        ProcWorkersControl {
            daemon: self.clone(),
        }
    }

    pub(super) fn proc_workers_snapshot(&self) -> ProcWorkersSnapshot {
        let runtime = self
            .inner
            .proc_workers
            .lock()
            .expect("proc workers mutex poisoned");

        let configured_handles = runtime.handles.len();
        let running_handles = runtime.handles.iter().filter(|h| !h.is_finished()).count();
        let shutdown_requested = runtime.shutdown.is_cancelled();
        let state = if running_handles > 0 {
            WorkerState::Running
        } else if shutdown_requested || configured_handles > 0 {
            WorkerState::Stopped
        } else {
            WorkerState::Unknown
        };

        ProcWorkersSnapshot {
            method: runtime.current_method,
            state,
            configured_handles,
            running_handles,
            shutdown_requested,
        }
    }

    pub(super) fn control_proc_workers_sync(&self, command: WorkerCommand) -> WorkerCommandResult {
        let mut runtime = self
            .inner
            .proc_workers
            .lock()
            .expect("proc workers mutex poisoned");

        runtime.handles.retain(|h| !h.is_finished());

        match command {
            WorkerCommand::Stop => {
                runtime.shutdown.cancel();
                for worker in &runtime.handles {
                    worker.stop();
                }
                WorkerCommandResult::Applied
            }
            WorkerCommand::Start => {
                if runtime.shutdown.is_cancelled() {
                    runtime.shutdown = CancellationToken::new();
                    runtime.handles.clear();
                }

                if runtime.handles.is_empty() {
                    let method = runtime.current_method;
                    runtime.handles =
                        self.spawn_proc_worker_handles(method, runtime.shutdown.clone());
                }

                WorkerCommandResult::Applied
            }
            WorkerCommand::Probe => WorkerCommandResult::Applied,
        }
    }

    pub(super) async fn reconfigure_proc_workers(
        &self,
        method: Option<ProcMonitorMethod>,
    ) -> Result<()> {
        let previous_method = {
            let runtime = self
                .inner
                .proc_workers
                .lock()
                .expect("proc workers mutex poisoned");
            runtime.current_method
        };

        let to_join = {
            let mut runtime = self
                .inner
                .proc_workers
                .lock()
                .expect("proc workers mutex poisoned");

            if let Some(method) = method
                && runtime.current_method == method
                && runtime.handles.iter().any(|handle| !handle.is_finished())
            {
                return Ok(());
            }

            debug!("monitor.End()");
            let old_shutdown = std::mem::replace(&mut runtime.shutdown, CancellationToken::new());
            old_shutdown.cancel();
            let to_join = std::mem::take(&mut runtime.handles);

            if let Some(method) = method {
                runtime.current_method = method;
                runtime.handles = self.spawn_proc_worker_handles(method, runtime.shutdown.clone());
            }

            to_join
        };

        if !to_join.is_empty() {
            let _ = tokio::task::spawn_blocking(move || {
                for worker in to_join {
                    let _ = worker.join();
                }
            })
            .await;
        }

        if let Some(method) = method {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let running = {
                let runtime = self
                    .inner
                    .proc_workers
                    .lock()
                    .expect("proc workers mutex poisoned");
                runtime.handles.iter().any(|handle| !handle.is_finished())
            };

            if !running {
                warn!(requested = ?method, fallback = ?previous_method, "process monitor workers failed to start; rolling back");
                notify(NotifyState::Status(
                    "Process monitor reconfigure failed; rolling back",
                ));
                if previous_method != method {
                    let failed_handles = {
                        let mut runtime = self
                            .inner
                            .proc_workers
                            .lock()
                            .expect("proc workers mutex poisoned");
                        runtime.shutdown.cancel();
                        std::mem::take(&mut runtime.handles)
                    };

                    if !failed_handles.is_empty() {
                        let _ = tokio::task::spawn_blocking(move || {
                            for worker in failed_handles {
                                let _ = worker.join();
                            }
                        })
                        .await;
                    }

                    let mut runtime = self
                        .inner
                        .proc_workers
                        .lock()
                        .expect("proc workers mutex poisoned");
                    runtime.current_method = previous_method;
                    runtime.shutdown = CancellationToken::new();
                    runtime.handles =
                        self.spawn_proc_worker_handles(previous_method, runtime.shutdown.clone());
                }
                return Err(anyhow::anyhow!(
                    "failed to start process monitor workers for {:?}",
                    method
                ));
            }

            let method_label = match method {
                ProcMonitorMethod::Proc => "/proc",
                ProcMonitorMethod::Audit => "audit",
                ProcMonitorMethod::Ebpf => "ebpf",
            };
            info!("Process monitor method {method_label}");
            info!(method = ?method, "reconfigured process monitor workers");
            notify(NotifyState::Status(&format!(
                "Process monitor reconfigured: {method_label}"
            )));
        } else {
            info!("stopped process monitor workers");
            notify(NotifyState::Status("Process monitor workers stopped"));
        }

        Ok(())
    }

    pub(super) async fn stop_proc_workers(&self) {
        let to_join = {
            let mut runtime = self
                .inner
                .proc_workers
                .lock()
                .expect("proc workers mutex poisoned");
            runtime.shutdown.cancel();
            std::mem::take(&mut runtime.handles)
        };

        if to_join.is_empty() {
            return;
        }

        let _ = tokio::task::spawn_blocking(move || {
            for worker in to_join {
                let _ = worker.join();
            }
        })
        .await;
    }
}

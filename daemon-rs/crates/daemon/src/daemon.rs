use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::{
    bus::Bus,
    services::{
        client::UiSessionService, config::ConfigService, connection::ConnectionService,
        dns::DnsService, firewall::FirewallService, process::ProcessService, rule::RuleService,
        stats::StatsService, subscription::SubscriptionService, task,
    },
    tunables::RuntimeTunables,
    workers::runtime::control::{OneShotWorker, WorkerControl},
};

mod bootstrap;
mod kernel_pipeline;
mod probes;
mod proc_workers;
mod reload;
mod serve;
mod signals;
mod startup;
mod tasks;
mod worker_startup;

pub(crate) use kernel_pipeline::{
    KernelPipeline, KernelPipelineDropStats, KernelPipelineIngressStats, ProcessKernelEvent,
};
pub(crate) use proc_workers::ProcWorkersRuntime;

#[derive(Clone)]
pub struct Daemon {
    pub(crate) inner: Arc<DaemonInner>,
}

pub(crate) struct DaemonInner {
    pub(crate) config: ConfigService,
    pub(crate) ui_session: UiSessionService,
    pub(crate) nfqueue_num: u16,
    pub(crate) default_action: crate::config::DefaultAction,
    pub(crate) audit_socket_path: std::path::PathBuf,
    pub(crate) proc_workers: Arc<std::sync::Mutex<ProcWorkersRuntime>>,
    pub(crate) bus: Bus,
    pub(crate) rules: RuleService,
    pub(crate) connections: ConnectionService,
    pub(crate) process: ProcessService,
    pub(crate) dns: DnsService,
    pub(crate) stats: StatsService,
    pub(crate) firewall: FirewallService,
    pub(crate) subscriptions: SubscriptionService,
    pub(crate) task_runtime: task::TaskRuntimeService,
    pub(crate) tunables: RuntimeTunables,
    pub(crate) shutdown: CancellationToken,
}

impl Daemon {
    const STARTUP_UI_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    const STARTUP_UI_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    fn boxed_one_shot_worker<T>(worker: T) -> Box<dyn WorkerControl>
    where
        T: WorkerControl + OneShotWorker + 'static,
    {
        Box::new(worker)
    }

    pub async fn run(client_addr: Option<&str>) -> Result<()> {
        let (daemon, rx) = Self::bootstrap(client_addr).await?;
        daemon.serve(rx).await
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }
}

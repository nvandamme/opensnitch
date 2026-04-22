use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::{
    bus::Bus,
    services::{
        client::{AlertBuffer, ClientService}, config::ConfigService, connection::ConnectionService,
        dns::DnsService, firewall::FirewallService, process::ProcessService, rule::RuleService,
        stats::StatsService, subscription::SubscriptionService, task,
    },
    tunables::RuntimeTunables,
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
    KernelPipeline, KernelPipelineCounters, KernelPipelineDropStats, KernelPipelineIngressStats,
    ProcessKernelEvent,
};
pub(crate) use proc_workers::ProcWorkersRuntime;

#[derive(Clone)]
pub struct Daemon {
    pub(crate) runtime: Arc<DaemonRuntime>,
}

pub(crate) struct DaemonRuntime {
    pub(crate) config: ConfigService,
    pub(crate) client: ClientService,
    pub(crate) nfqueue_num: u16,
    pub(crate) default_action: crate::config::DefaultAction,
    pub(crate) audit_socket_path: std::path::PathBuf,
    pub(crate) proc_workers: Arc<std::sync::Mutex<ProcWorkersRuntime>>,
    pub(crate) bus: Bus,
    pub(crate) alert_buffer: AlertBuffer,
    pub(crate) kernel_pipeline_counters: Arc<KernelPipelineCounters>,
    pub(crate) rules: RuleService,
    pub(crate) connections: ConnectionService,
    pub(crate) process: ProcessService,
    pub(crate) dns: DnsService,
    pub(crate) stats: StatsService,
    pub(crate) firewall: FirewallService,
    pub(crate) subscriptions: SubscriptionService,
    pub(crate) tasks: task::TaskService,
    pub(crate) tunables: RuntimeTunables,
    pub(crate) shutdown: CancellationToken,
}

impl Daemon {
    const STARTUP_UI_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    const STARTUP_UI_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    pub async fn start(client_addr: Option<&str>) -> Result<()> {
        let (daemon, rx) = Self::bootstrap(client_addr).await?;
        daemon.serve(rx).await
    }

    pub async fn stop(&self) {
        self.runtime.shutdown.cancel();
    }

    /// Reload runtime services from `updated` config.
    ///
    /// `scope: None` — full reload, every service is unconditionally re-applied (SIGHUP).
    /// `scope: Some(_)` — selective reload, only named services are reloaded.
    pub(crate) async fn reload(
        &self,
        updated: &crate::config::Config,
        scope: Option<reload::ReloadScope>,
    ) -> Result<(), reload::ReloadError> {
        self.reload_impl(updated, scope).await
    }
}

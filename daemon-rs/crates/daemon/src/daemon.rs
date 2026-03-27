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

/// CLI overrides parallel to the Go daemon's flag package:
///
///   --config-file              <path>       Config JSON file (highest priority).
///   --rules-path               <path>       Rules directory override.
///   --ui-socket                <addr>       UI gRPC address.
///   --metrics-prometheus-addr  <host:port>  Prometheus /metrics listen address.
///   --metrics-push-url         <url>        Push exporter endpoint.
///   --metrics-push-format      <fmt>        Push format (pushgateway|pushgateway-proto|influxdb).
///   --metrics-push-job         <name>       Push-gateway job label.
///   --metrics-push-token       <token>      Push auth token.
///   --metrics-push-gzip                     Enable gzip compression on push bodies.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub config_file: Option<std::path::PathBuf>,
    pub rules_path:  Option<std::path::PathBuf>,
    pub ui_socket:   Option<String>,
    pub metrics:     crate::models::metrics_config::MetricsCliOverrides,
}
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
    /// Metrics export config loaded from `metrics.json` at startup (§7 baseline JSON layer).
    #[cfg_attr(not(feature = "metrics-export"), allow(dead_code))]
    pub(crate) metrics_config: crate::models::metrics_config::MetricsConfig,
    /// Metrics CLI overrides supplied via `--metrics-*` flags (§7 highest tier; overrides env vars and JSON).
    #[cfg_attr(not(feature = "metrics-export"), allow(dead_code))]
    pub(crate) metrics_cli: crate::models::metrics_config::MetricsCliOverrides,
    /// Hot-reload handle for the Prometheus scrape HTTP server.
    ///
    /// Written once by `spawn_stats_flow` and updated on SIGHUP via
    /// `reload_metrics_server`.  The exporter inside is kept alive across
    /// server restarts so the stats flow can continue feeding snapshots even
    /// when the listen address changes.
    #[cfg(feature = "metrics-export")]
    pub(crate) metrics_server: std::sync::Mutex<Option<MetricsServerSlot>>,
}

/// Hot-reload state for the Prometheus scrape HTTP server.
///
/// Stored inside `DaemonRuntime` and updated by `reload_metrics_server` on SIGHUP.
/// The `exporter` field is long-lived and shared with the running `StatsFlow`; only
/// the TCP listener is cancelled and restarted when the listen address changes.
#[cfg(feature = "metrics-export")]
pub(crate) struct MetricsServerSlot {
    /// Shared exporter — survives server address changes.  The `StatsFlow` holds
    /// another `Arc` clone and keeps calling `export_snapshot` regardless of
    /// whether the HTTP server is running.
    pub(crate) exporter: std::sync::Arc<
        crate::platform::adapters::stats_exporter_prometheus::PrometheusStatsExporter,
    >,
    /// Currently bound address, or `None` when the server is not running.
    pub(crate) effective_addr: Option<std::net::SocketAddr>,
    /// Cancellation token for the current HTTP server task.
    /// `None` when the server is not running (addr not configured).
    pub(crate) server_ct: Option<CancellationToken>,
}

impl Daemon {
    const STARTUP_UI_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    const STARTUP_UI_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    pub async fn start(cli: CliOverrides) -> Result<()> {
        let (daemon, rx) = Self::bootstrap(cli).await?;
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

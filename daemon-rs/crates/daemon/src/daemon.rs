use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::{
    bus::Bus,
    models::config::runtime::FirewallPersistenceMode,
    services::{
        audit::AuditService,
        client::{AlertBuffer, ClientService},
        config::ConfigService,
        connection::ConnectionService,
        dns::DnsService,
        firewall::FirewallService,
        process::ProcessService,
        rule::RuleService,
        stats::StatsService,
        subscription::SubscriptionService,
        task,
    },
    tunables::RuntimeTunables,
};

mod bootstrap;
mod kernel_pipeline;
mod migration;
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
#[allow(unused_imports)] // used by tests via crate::daemon::
pub(crate) use migration::{
    RuleMigrationDecision, classify_rule_for_ownerless_migration,
    load_ownerless_rule_migration_plan,
};

/// CLI overrides parallel to the Go daemon's flag package:
///
///   --config-file              <path>       Config JSON file (highest priority).
///   --rules-path               <path>       Rules directory override.
///   --ui-socket                <addr>       UI gRPC address.
///   --auth-mode                <mode>       Client authorization mode override (legacy|local-only|local+remote).
///   --main-storage-format      <format>     Main storage format override (json|yaml|toml).
///   --migrate-ownerless-rules               Run one-shot legacy ownerless rule migration.
///   --migrate-owner-uid        <uid>        Target owner UID for migration mode.
///   --migrate-write                         Persist migration changes (default is dry-run).
///   --metrics-prometheus-addr  <host:port>  Prometheus /metrics listen address.
///   --metrics-push-url         <url>        Push exporter endpoint.
///   --metrics-push-format      <fmt>        Push format (pushgateway|pushgateway-openmetrics|pushgateway-proto).
///   --metrics-push-job         <name>       Push-gateway job label.
///   --metrics-push-token       <token>      Push auth token.
///   --metrics-push-gzip                     Enable gzip compression on push bodies.
///   --audit-sink-file          <path>       Append NDJSON audit records to this file.
///   --audit-sink-syslog                     Enable local syslog as an audit sink.
///   --audit-sink-log                        Enable tracing log-line audit sink (default on).
///   --firewall-persistence-mode <mode>      Firewall persistence mode override (live-only|durable).
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub config_file: Option<std::path::PathBuf>,
    pub rules_path: Option<std::path::PathBuf>,
    pub ui_socket: Option<String>,
    pub auth_mode: Option<String>,
    pub firewall_persistence_mode: Option<String>,
    pub main_storage_format: Option<String>,
    pub rule_migration: RuleMigrationCliOverrides,
    pub metrics: crate::models::metrics::config::MetricsCliOverrides,
    pub audit: AuditCliOverrides,
}

#[derive(Debug, Default)]
pub struct RuleMigrationCliOverrides {
    pub ownerless_rules: bool,
    pub owner_uid: Option<String>,
    pub write: bool,
}

/// CLI overrides for audit sink selection.
///
/// All three sinks are additive: setting any one of these enables/overrides
/// the config-file setting for that specific sink.
#[derive(Debug, Default)]
pub struct AuditCliOverrides {
    /// Append NDJSON records to this file path.
    pub sink_file: Option<std::path::PathBuf>,
    /// Enable syslog sink when `Some(true)`.
    pub sink_syslog: Option<bool>,
    /// Enable log-line (tracing) sink when `Some(true)`.
    pub sink_log_lines: Option<bool>,
    /// Enable verbose hot-path audit events when `Some(true)`.
    pub verbose_hot_path: Option<bool>,
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
    pub(crate) audit: AuditService,
    /// Active audit event sinks (file / syslog / log-lines), built from
    /// the resolved `AuditSinkConfig` (config file → env vars → CLI overrides).
    pub(crate) audit_sinks: crate::services::audit::AuditSinks,
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
    // Read only inside metrics feature-gated blocks in tasks.rs.
    // blocks in tasks.rs; dead when both metrics features are off.
    #[cfg(any(
        feature = "metrics-http-serve-text",
        feature = "metrics-http-serve-openmetrics",
        feature = "metrics-http-serve-protobuf",
        feature = "metrics-http-push-text",
        feature = "metrics-http-push-openmetrics",
        feature = "metrics-http-push-protobuf",
        feature = "metrics-http-push-influxdb",
        feature = "metrics-syslog"
    ))]
    pub(crate) metrics_config: crate::models::metrics::config::MetricsConfig,
    /// Metrics CLI overrides supplied via `--metrics-*` flags (§7 highest tier; overrides env vars and JSON).
    // Read only inside metrics feature-gated blocks in tasks.rs.
    // blocks in tasks.rs; dead when both metrics features are off.
    #[cfg(any(
        feature = "metrics-http-serve-text",
        feature = "metrics-http-serve-openmetrics",
        feature = "metrics-http-serve-protobuf",
        feature = "metrics-http-push-text",
        feature = "metrics-http-push-openmetrics",
        feature = "metrics-http-push-protobuf",
        feature = "metrics-http-push-influxdb",
        feature = "metrics-syslog"
    ))]
    pub(crate) metrics_cli: crate::models::metrics::config::MetricsCliOverrides,
    /// Hot-reload handle for the Prometheus scrape HTTP server.
    ///
    /// Written once by `spawn_stats_flow` and updated on SIGHUP via
    /// `reload_metrics_server`.  The exporter inside is kept alive across
    /// server restarts so the stats flow can continue feeding snapshots even
    /// when the listen address changes.
    #[cfg(any(
        feature = "metrics-http-serve-text",
        feature = "metrics-http-serve-openmetrics",
        feature = "metrics-http-serve-protobuf"
    ))]
    pub(crate) metrics_server: std::sync::Mutex<Option<MetricsServerSlot>>,
}

/// Hot-reload state for the Prometheus scrape HTTP server.
///
/// Stored inside `DaemonRuntime` and updated by `reload_metrics_server` on SIGHUP.
/// The `exporter` field is long-lived and shared with the running `StatsFlow`; only
/// the TCP listener is cancelled and restarted when the listen address changes.
#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf"
))]
pub(crate) struct MetricsServerSlot {
    /// Shared exporter — survives server address changes.  The `StatsFlow` holds
    /// another `Arc` clone and keeps calling `export_snapshot` regardless of
    /// whether the HTTP server is running.
    pub(crate) exporter:
        std::sync::Arc<crate::platform::stats::exporters::http_serve::PrometheusStatsExporter>,
    /// Currently bound address, or `None` when the server is not running.
    pub(crate) effective_addr: Option<std::net::SocketAddr>,
    /// Cancellation token for the current HTTP server task.
    /// `None` when the server is not running (addr not configured).
    pub(crate) server_ct: Option<CancellationToken>,
}

impl Daemon {
    const STARTUP_CLIENT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    const STARTUP_CLIENT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    pub async fn start(cli: CliOverrides) -> Result<()> {
        if cli.rule_migration.ownerless_rules {
            return Self::run_ownerless_rule_migration(cli).await;
        }
        let (daemon, rx) = Self::bootstrap(cli).await?;
        daemon.serve(rx).await
    }

    pub async fn stop(&self) {
        let config = self.runtime.config.get_snapshot();
        let cleanup_runtime_rules = matches!(
            config.firewall_persistence_mode,
            FirewallPersistenceMode::LiveOnly
        );

        #[cfg(feature = "openwrt")]
        let cleanup_runtime_rules = cleanup_runtime_rules
            && !matches!(
                config.firewall_backend,
                crate::platform::firewall::state::FirewallBackend::OpenWrtUci
            );

        if cleanup_runtime_rules
            && let Err(err) = self
                .runtime
                .firewall
                .cleanup_runtime_rules_for_shutdown()
                .await
        {
            tracing::warn!(
                error = %err,
                "failed to clean up non-durable runtime firewall rules during shutdown"
            );
        }

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

use tracing::{error, info};

use super::Daemon;
use crate::{
    config::{Config, DefaultAction},
    services::{lifecycle::ServiceRuntimeControl, storage::StorageService},
    utils::config_reload::{
        RuntimeApplyMessageContext, RuntimeApplyPolicy, RuntimeApplyStage,
        apply_runtime_config_services, apply_runtime_core, runtime_apply_stage_messages,
    },
    utils::systemd_notify::{NotifyState, notify},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadTarget {
    Config,
    Client,
    Rules,
    Connections,
    Dns,
    Stats,
    Firewall,
    Process,
    Subscription,
    Task,
    Storage,
}

impl ReloadTarget {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "config" => Some(Self::Config),
            // Keep `ui_session` as a legacy alias for backward compatibility.
            "client" | "client_session" | "ui_session" => Some(Self::Client),
            "rules" => Some(Self::Rules),
            "connections" => Some(Self::Connections),
            "dns" => Some(Self::Dns),
            "stats" => Some(Self::Stats),
            "firewall" => Some(Self::Firewall),
            "process" => Some(Self::Process),
            "subscription" => Some(Self::Subscription),
            "task" => Some(Self::Task),
            "storage" => Some(Self::Storage),
            _ => None,
        }
    }

    fn all() -> &'static [Self] {
        const ALL: [ReloadTarget; 11] = [
            ReloadTarget::Config,
            ReloadTarget::Client,
            ReloadTarget::Rules,
            ReloadTarget::Connections,
            ReloadTarget::Dns,
            ReloadTarget::Stats,
            ReloadTarget::Firewall,
            ReloadTarget::Process,
            ReloadTarget::Subscription,
            ReloadTarget::Task,
            ReloadTarget::Storage,
        ];
        &ALL
    }
}

/// Selective reload scope for [`Daemon::reload`].
/// When `None` is passed to `reload`, every service is re-applied (full reload).
/// When `Some(scope)` is passed, only services listed in `scope.services`
/// are re-applied by the service runtime control layer.
#[derive(Debug, Clone)]
pub(crate) struct ReloadScope {
    pub(crate) services: Vec<String>,
}

impl ReloadScope {
    fn reloads(&self, target: ReloadTarget) -> bool {
        self.services
            .iter()
            .filter_map(|name| ReloadTarget::parse(name))
            .any(|current| current == target)
    }

    fn parsed_targets(&self) -> Vec<ReloadTarget> {
        let mut parsed = Vec::new();
        for name in &self.services {
            match ReloadTarget::parse(name) {
                Some(target) if !parsed.contains(&target) => parsed.push(target),
                Some(_) => {}
                None => {
                    tracing::warn!(
                        service = %name,
                        "unknown service in reload scope, skipping"
                    );
                }
            }
        }
        parsed
    }
}

#[derive(Debug)]
pub(crate) enum ReloadError {
    /// Config could not be loaded or parsed.
    // Retained explicit error variant for config-load stage contract completeness.
    #[allow(dead_code)]
    ConfigLoad(anyhow::Error),
    /// One or more service apply stages failed.
    ServicesApply {
        stage: RuntimeApplyStage,
        error: anyhow::Error,
    },
    /// Process worker reconfiguration failed.
    ProcWorkers(anyhow::Error),
    /// Service runtime-control hook failed.
    ServiceRuntime(anyhow::Error),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigLoad(err) => write!(f, "config load failed: {err}"),
            Self::ServicesApply { stage, error } => {
                write!(f, "service apply failed at stage {stage:?}: {error}")
            }
            Self::ProcWorkers(err) => write!(f, "proc worker reconfiguration failed: {err}"),
            Self::ServiceRuntime(err) => write!(f, "service runtime reload failed: {err}"),
        }
    }
}

impl Daemon {
    /// Reload runtime services according to `scope`.
    ///
    /// `None` unconditionally re-applies every service
    /// (singletons → logging → rules → firewall → proc workers).
    ///
    /// `Some(scope)` uses service-name matching to selectively trigger
    /// runtime control hooks and optional firewall/proc reconfiguration.
    pub(super) async fn reload_impl(
        &self,
        updated: &Config,
        scope: Option<ReloadScope>,
    ) -> Result<(), ReloadError> {
        let should_reload_fw = scope
            .as_ref()
            .map(|s| s.reloads(ReloadTarget::Firewall))
            .unwrap_or(true);
        let should_reload_proc = scope
            .as_ref()
            .map(|s| s.reloads(ReloadTarget::Process))
            .unwrap_or(true);

        apply_runtime_core(updated, &self.runtime.stats);

        let apply_report = apply_runtime_config_services(
            updated,
            &self.runtime.rules,
            &self.runtime.firewall,
            RuntimeApplyPolicy::StopAfterRulesError,
            should_reload_fw,
        )
        .await;

        for (stage, err) in apply_report.into_stage_errors() {
            if !matches!(stage, RuntimeApplyStage::Logging) {
                return Err(ReloadError::ServicesApply { stage, error: err });
            }
            error!("non-fatal: failed to apply logging config during reload: {err}");
        }

        if should_reload_proc {
            self.reconfigure_proc_workers(Some(updated.proc_monitor_method))
                .await
                .map_err(ReloadError::ProcWorkers)?;
        }

        self.reload_service_runtime_controls(updated, scope)
            .await
            .map_err(ReloadError::ServiceRuntime)?;

        Ok(())
    }

    async fn reload_service_runtime_controls(
        &self,
        updated: &Config,
        scope: Option<ReloadScope>,
    ) -> anyhow::Result<()> {
        let targets = scope
            .as_ref()
            .map(ReloadScope::parsed_targets)
            .unwrap_or_else(|| ReloadTarget::all().to_vec());

        for target in targets {
            match target {
                ReloadTarget::Config => {
                    let mut config = self.runtime.config.clone();
                    ServiceRuntimeControl::reload(&mut config, updated.clone()).await?;
                }
                ReloadTarget::Client => {
                    let mut client = self.runtime.client.clone();
                    ServiceRuntimeControl::reload(&mut client, updated.clone()).await?;
                }
                ReloadTarget::Rules => {
                    let mut rules = self.runtime.rules.clone();
                    ServiceRuntimeControl::reload(&mut rules, ()).await?;
                }
                ReloadTarget::Connections => {
                    let mut connections = self.runtime.connections.clone();
                    ServiceRuntimeControl::reload(&mut connections, ()).await?;
                }
                ReloadTarget::Dns => {
                    let mut dns = self.runtime.dns.clone();
                    ServiceRuntimeControl::reload(&mut dns, ()).await?;
                }
                ReloadTarget::Stats => {
                    let mut stats = self.runtime.stats.clone();
                    ServiceRuntimeControl::reload(&mut stats, ()).await?;
                }
                ReloadTarget::Firewall => {
                    let mut firewall = self.runtime.firewall.clone();
                    ServiceRuntimeControl::reload(&mut firewall, ()).await?;
                }
                ReloadTarget::Process => {
                    let mut process = self.runtime.process.clone();
                    ServiceRuntimeControl::reload(&mut process, ()).await?;
                }
                ReloadTarget::Subscription => {
                    let mut subscriptions = self.runtime.subscriptions.clone();
                    ServiceRuntimeControl::reload(&mut subscriptions, ()).await?;
                }
                ReloadTarget::Task => {
                    let mut tasks = self.runtime.tasks.clone();
                    ServiceRuntimeControl::reload(&mut tasks, ()).await?;
                }
                ReloadTarget::Storage => {
                    let mut storage = StorageService::global();
                    ServiceRuntimeControl::reload(&mut storage, ()).await?;
                }
            }
        }

        Ok(())
    }

    pub(super) async fn reload_runtime_after_sighup(&self) {
        notify(NotifyState::Reloading(Some(
            "SIGHUP received, reloading runtime config...",
        )));
        info!("SIGHUP received, reloading runtime config");

        let updated = match self.runtime.config.reload().await {
            Ok(config) => config,
            Err(err) => {
                error!("failed to reload config from disk after SIGHUP: {err}");
                notify(NotifyState::Status(
                    "SIGHUP reload failed while reading config",
                ));
                return;
            }
        };

        if let Err(err) = self.reload(&updated, None).await {
            let (external, stage) = match &err {
                ReloadError::ServicesApply { stage, .. } => {
                    let messages =
                        runtime_apply_stage_messages(RuntimeApplyMessageContext::Sighup, *stage);
                    (messages.external, Some(*stage))
                }
                ReloadError::ProcWorkers(_) => (
                    "SIGHUP reload failed while reconfiguring process monitor",
                    None,
                ),
                ReloadError::ServiceRuntime(_) => (
                    "SIGHUP reload failed while refreshing service runtime state",
                    None,
                ),
                ReloadError::ConfigLoad(_) => unreachable!("config already loaded"),
            };
            error!("SIGHUP reload failed: {err}");
            notify(NotifyState::Status(external));
            let _ = stage;
            return;
        }

        // Reload metrics.json and re-wire the Prometheus scrape server if the
        // listen address has changed (or was newly added / removed).
        #[cfg(any(
            feature = "metrics-http-serve-text",
            feature = "metrics-http-serve-openmetrics",
            feature = "metrics-http-serve-protobuf"
        ))]
        self.reload_metrics_server();

        info!("SIGHUP reload completed");
        notify(NotifyState::Ready(Some("SIGHUP reload complete")));
    }

    /// Re-read `metrics.json` and reconcile the Prometheus scrape HTTP server.
    ///
    /// - If the effective listen address is unchanged, nothing happens.
    /// - If the address changed (or was added): the old server is cancelled and a
    ///   new one is spawned on the new address, reusing the same
    ///   [`PrometheusStatsExporter`] so the running `StatsFlow` continues
    ///   delivering snapshots without interruption.
    /// - If the address was removed: the server is cancelled.
    ///
    /// Push exporter configuration is not hot-reloaded; a daemon restart is
    /// required for push URL / format / credential changes.
    #[cfg(any(
        feature = "metrics-http-serve-text",
        feature = "metrics-http-serve-openmetrics",
        feature = "metrics-http-serve-protobuf"
    ))]
    pub(super) fn reload_metrics_server(&self) {
        use crate::models::metrics_config::MetricsConfig;
        use crate::platform::stats::exporters::http_serve::{
            PROMETHEUS_ADDR_ENV, PrometheusStatsExporter,
        };

        let config_path = self.runtime.config.get_snapshot().config_path.clone();

        let new_mc = match MetricsConfig::load_sibling(&config_path) {
            Ok(mc) => mc,
            Err(err) => {
                tracing::warn!("metrics SIGHUP reload: failed to load metrics.json: {err}");
                return;
            }
        };

        let cli = &self.runtime.metrics_cli;

        // §7 resolution (same as spawn_stats_flow): CLI > env var > JSON config.
        let new_addr_str: Option<String> = cli
            .prometheus_addr
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                std::env::var(PROMETHEUS_ADDR_ENV)
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| new_mc.prometheus.addr.clone().filter(|s| !s.is_empty()));

        let new_addr: Option<std::net::SocketAddr> = new_addr_str.and_then(|s| {
            s.parse().map_err(|e| {
                tracing::warn!(addr = %s, "metrics SIGHUP reload: invalid prometheus addr: {e}");
            }).ok()
        });

        let mut slot = self.runtime.metrics_server.lock().unwrap();

        let old_addr = slot.as_ref().and_then(|s| s.effective_addr);

        match (old_addr, new_addr) {
            (Some(old), Some(new)) if old == new => {
                tracing::debug!(addr = %old, "metrics SIGHUP reload: addr unchanged, skipping");
            }
            (_, Some(new_addr)) => {
                // Cancel old server (if any) while preserving the exporter Arc.
                let old_exporter = slot.as_ref().map(|s| s.exporter.clone());
                if let Some(old_slot) = slot.take() {
                    if let Some(ct) = old_slot.server_ct {
                        ct.cancel();
                    }
                }
                let exp = old_exporter.unwrap_or_else(PrometheusStatsExporter::new);
                let server_ct = self.runtime.shutdown.child_token();
                exp.clone()
                    .spawn_metrics_server(new_addr, server_ct.clone());
                *slot = Some(super::MetricsServerSlot {
                    exporter: exp,
                    effective_addr: Some(new_addr),
                    server_ct: Some(server_ct),
                });
                tracing::info!(
                    addr = %new_addr,
                    "metrics SIGHUP reload: prometheus scrape server restarted"
                );
            }
            (Some(_), None) => {
                // Address was removed — shut down the server.
                if let Some(old_slot) = slot.take() {
                    if let Some(ct) = old_slot.server_ct {
                        ct.cancel();
                    }
                }
                tracing::info!("metrics SIGHUP reload: prometheus scrape server disabled");
            }
            (None, None) => {
                // Was disabled, still disabled — nothing to do.
            }
        }
    }

    pub(super) fn parse_default_action_from_client_config(
        raw_config_json: &str,
    ) -> Option<DefaultAction> {
        DefaultAction::from_raw_config_json(raw_config_json)
    }
}

impl From<crate::commands::control::DaemonReloadScope> for ReloadScope {
    fn from(s: crate::commands::control::DaemonReloadScope) -> Self {
        Self {
            services: s.services,
        }
    }
}

/// Adapter that wraps a [`Daemon`] clone and implements [`DaemonReloadPort`] so
/// the commands layer can call `Daemon::reload` without importing `Daemon` directly.
pub(super) struct DaemonReloadPortAdapter {
    pub(super) daemon: Daemon,
}

impl crate::commands::control::DaemonReloadPort for DaemonReloadPortAdapter {
    fn daemon_reload<'a>(
        &'a self,
        updated: &'a crate::config::Config,
        scope: Option<crate::commands::control::DaemonReloadScope>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        let daemon = self.daemon.clone();
        let updated = updated.clone();
        Box::pin(async move {
            daemon
                .reload(&updated, scope.map(Into::into))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
    }
}

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use transport_wire_core::{ClientTransportConnectorPort, ClientTransportPort};

use crate::{
    daemon::{KernelPipelineDropStats, KernelPipelineIngressStats},
    models::audit::{
        AuditEvent, AuditEventKind, KernelAction, StatsFlowAction, StatsFlowLifecycle,
        StorageLifecycle,
    },
    services::dns::DnsService,
    services::{
        audit::AuditService,
        client::{ClientService, ClientTransportConnector, WireSessionCache},
        config::ConfigService,
        rule::RuleService,
        stats::StatsService,
        storage::StorageService,
    },
    utils::lru_cache::global_dual_layer_metrics_snapshot,
};

pub(crate) use crate::models::worker_telemetry::WorkerTelemetrySnapshot;

use crate::platform::ports::stats_exporter_port::StatsExporterPort;
use crate::services::client::transport::ClientPingRequest;

pub(crate) struct StatsFlow {
    shutdown: CancellationToken,
    config: ConfigService,
    client_service: ClientService,
    rules: RuleService,
    stats: StatsService,
    ingress_stats_snapshot: Arc<dyn Fn() -> KernelPipelineIngressStats + Send + Sync>,
    drop_stats_snapshot: Arc<dyn Fn() -> KernelPipelineDropStats + Send + Sync>,
    worker_name: &'static str,
    worker_snapshot: Arc<dyn Fn() -> WorkerTelemetrySnapshot + Send + Sync>,
    dns: DnsService,
    audit: AuditService,
    /// Optional stats snapshot exporter (Prometheus scrape, push-gateway, Loki, etc.)
    stats_exporter: Option<Arc<dyn StatsExporterPort>>,
}

impl StatsFlow {
    pub(crate) fn new(
        shutdown: CancellationToken,
        config: ConfigService,
        client_service: ClientService,
        rules: RuleService,
        stats: StatsService,
        ingress_stats_snapshot: Arc<dyn Fn() -> KernelPipelineIngressStats + Send + Sync>,
        drop_stats_snapshot: Arc<dyn Fn() -> KernelPipelineDropStats + Send + Sync>,
        worker_name: &'static str,
        worker_snapshot: Arc<dyn Fn() -> WorkerTelemetrySnapshot + Send + Sync>,
        dns: DnsService,
        audit: AuditService,
    ) -> Self {
        Self {
            shutdown,
            config,
            client_service,
            rules,
            stats,
            ingress_stats_snapshot,
            drop_stats_snapshot,
            worker_name,
            worker_snapshot,
            stats_exporter: None,
            dns,
            audit,
        }
    }

    /// Attach an optional stats exporter (Prometheus, Grafana Mimir, etc.).
    ///
    /// The exporter receives every metrics snapshot produced by
    /// the 1-second emission cycle.  When not attached, the flow behaves
    /// identically to before.  Call sites that do not need the exporter
    /// do not need to change.
    ///
    /// See `platform::ports::stats_exporter_port::StatsExporterPort`.
    // Called only inside metrics exporter wiring in daemon/tasks.rs; dead when both
    // metrics endpoint features are disabled.
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
    pub(crate) fn with_stats_exporter(mut self, exporter: Arc<dyn StatsExporterPort>) -> Self {
        self.stats_exporter = Some(exporter);
        self
    }

    pub(crate) fn spawn(self) -> JoinHandle<()> {
        let Self {
            shutdown,
            config,
            client_service,
            rules,
            stats,
            ingress_stats_snapshot,
            drop_stats_snapshot,
            worker_name,
            worker_snapshot,
            stats_exporter,
            dns,
            audit,
        } = self;

        tokio::spawn(async move {
            audit.emit(AuditEvent::cold(AuditEventKind::StatsFlowLifecycle(
                StatsFlowLifecycle::Started,
            )));
            let storage_shutdown = shutdown.clone();
            let storage_stats = stats.clone();
            let storage_audit = audit.clone();
            let mut storage_events = StorageService::global().subscribe_events();
            let mut storage_reload = StorageService::subscribe_global_reload();
            let storage_observer = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = storage_shutdown.cancelled() => break,
                        changed = storage_reload.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            let generation = *storage_reload.borrow_and_update();
                            storage_events = StorageService::global().subscribe_events();
                            storage_audit.emit(AuditEvent::cold(
                                AuditEventKind::StorageLifecycle(
                                    StorageLifecycle::StorageObserverRebound {
                                        reason: "storage-runtime-reload",
                                    },
                                ),
                            ));
                            debug!(generation, "rebound storage event subscriber after storage runtime reload");
                        }
                        storage_event = storage_events.recv() => {
                            match storage_event {
                                Ok(event) => {
                                    // FileRead / FileWritten audit emits belong at the
                                    // service-owned write sites (RuleService, ConfigService, etc.)
                                    // where the operation has domain context.  Emitting here
                                    // on every raw I/O event produces operational noise without
                                    // security value; reserved for verbose-audit mode.
                                    storage_stats.on_storage_event(event.operation);
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                    storage_audit.emit(AuditEvent::cold(
                                        AuditEventKind::StorageLifecycle(
                                            StorageLifecycle::StorageObserverLagged {
                                                skipped: skipped as u64,
                                            },
                                        ),
                                    ));
                                    warn!(skipped, "storage event subscriber lagged; events dropped");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    storage_events = StorageService::global().subscribe_events();
                                    storage_audit.emit(AuditEvent::cold(
                                        AuditEventKind::StorageLifecycle(
                                            StorageLifecycle::StorageObserverRebound {
                                                reason: "storage-event-bus-closed",
                                            },
                                        ),
                                    ));
                                    warn!("storage event bus closed; rebound stats storage observer to current storage runtime");
                                }
                            }
                        }
                    }
                }
            });

            let mut ping_id = 2_u64;
            let connector = ClientTransportConnector::new(WireSessionCache::default());
            let mut last_ingress_snapshot = ingress_stats_snapshot();
            let mut last_drop_snapshot = drop_stats_snapshot();
            let mut last_fast_allow = stats.fast_allow_count();
            let mut last_fast_deny = stats.fast_deny_count();
            let mut last_storage_events = stats.storage_event_counts();
            let mut last_cache_metrics = global_dual_layer_metrics_snapshot();
            let mut last_drop_log_at = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                        if last_drop_log_at.elapsed() >= std::time::Duration::from_secs(30) {
                            let current = drop_stats_snapshot();
                            let delta = current.saturating_delta(last_drop_snapshot);
                            let ingress_current = ingress_stats_snapshot();
                            let ingress_delta = ingress_current.saturating_delta(last_ingress_snapshot);
                            if delta.total() > 0 {
                                audit.emit(AuditEvent::cold(
                                    AuditEventKind::KernelAction(
                                        KernelAction::KernelPipelineDropsObserved {
                                            dns: delta.dns,
                                            process: delta.process,
                                            firewall: delta.firewall,
                                            total: delta.total(),
                                        },
                                    ),
                                ));
                                warn!(
                                    dns = delta.dns,
                                    process = delta.process,
                                    firewall = delta.firewall,
                                    total = delta.total(),
                                    "non-connect kernel pipeline drops observed"
                                );
                            }

                            if ingress_delta.total() > 0 {
                                let dns_drop_ratio_pct = if ingress_delta.dns == 0 {
                                    0.0
                                } else {
                                    (delta.dns as f64 * 100.0) / ingress_delta.dns as f64
                                };
                                let process_drop_ratio_pct = if ingress_delta.process == 0 {
                                    0.0
                                } else {
                                    (delta.process as f64 * 100.0) / ingress_delta.process as f64
                                };
                                let firewall_drop_ratio_pct = if ingress_delta.firewall == 0 {
                                    0.0
                                } else {
                                    (delta.firewall as f64 * 100.0)
                                        / ingress_delta.firewall as f64
                                };

                                debug!(
                                    ingress_dns = ingress_delta.dns,
                                    ingress_process = ingress_delta.process,
                                    ingress_firewall = ingress_delta.firewall,
                                    drop_dns = delta.dns,
                                    drop_process = delta.process,
                                    drop_firewall = delta.firewall,
                                    drop_ratio_dns_pct = dns_drop_ratio_pct,
                                    drop_ratio_process_pct = process_drop_ratio_pct,
                                    drop_ratio_firewall_pct = firewall_drop_ratio_pct,
                                    "non-connect kernel pipeline pressure evidence"
                                );
                            }

                            let fast_allow_total = stats.fast_allow_count();
                            last_ingress_snapshot = ingress_current;
                            let fast_allow_delta = fast_allow_total
                                .saturating_sub(last_fast_allow);
                            if fast_allow_delta > 0 {
                                debug!(
                                    delta = fast_allow_delta,
                                    total = fast_allow_total,
                                    "fast-allow attempts observed"
                                );
                            }

                            let fast_deny_total = stats.fast_deny_count();
                            let fast_deny_delta = fast_deny_total
                                .saturating_sub(last_fast_deny);
                            if fast_deny_delta > 0 {
                                debug!(
                                    delta = fast_deny_delta,
                                    total = fast_deny_total,
                                    "fast-drop attempts observed"
                                );
                            }

                            let snapshot = worker_snapshot();
                            debug!(
                                worker = worker_name,
                                state = snapshot.state,
                                method = ?snapshot.method,
                                dns_monitor_state = dns.dns_monitor_state_label(),
                                configured_handles = snapshot.configured_handles,
                                running_handles = snapshot.running_handles,
                                shutdown_requested = snapshot.shutdown_requested,
                                "worker state telemetry snapshot"
                            );

                            debug!(
                                worker = worker_name,
                                connected_client_sessions = client_service.connected_sessions_count(),
                                "client session telemetry snapshot"
                            );

                            let storage_events_total = stats.storage_event_counts();
                            let storage_delta = storage_events_total.saturating_delta(last_storage_events);
                            if storage_delta.total() > 0 {
                                debug!(
                                    reads = storage_delta.reads,
                                    writes = storage_delta.writes,
                                    deletes = storage_delta.deletes,
                                    scans = storage_delta.scans,
                                    "storage event activity snapshot"
                                );
                            }

                            let cache_metrics_total = global_dual_layer_metrics_snapshot();
                            let cache_metrics_delta = cache_metrics_total.saturating_delta(last_cache_metrics);
                            if cache_metrics_delta.total() > 0 {
                                debug!(
                                    hits = cache_metrics_delta.hits,
                                    misses = cache_metrics_delta.misses,
                                    "lru cache metrics snapshot"
                                );
                            }

                            last_drop_snapshot = current;
                            last_fast_allow = fast_allow_total;
                            last_fast_deny = fast_deny_total;
                            last_storage_events = storage_events_total;
                            last_cache_metrics = cache_metrics_total;
                            last_drop_log_at = tokio::time::Instant::now();
                        }

                        let rules_count = rules.rules_count() as u64;
                        let Some(metrics_snapshot) = stats.snapshot_if_pending(rules_count) else {
                            continue;
                        };

                        audit.emit(AuditEvent::cold(AuditEventKind::StatsFlowAction(
                            StatsFlowAction::SnapshotPublished {
                                connections: metrics_snapshot.stats.connections as u32,
                            },
                        )));

                        if let Some(ref exporter) = stats_exporter {
                            exporter.export_snapshot(&metrics_snapshot);
                        }

                        let req = ClientPingRequest {
                            id: ping_id,
                            stats: Some(metrics_snapshot.stats.into()),
                        };

                        let config_snapshot = config.get_snapshot();
                        let client_addr = config_snapshot.client_addr.as_str();
                        let mut client = match ClientTransportConnectorPort::connect_or_reuse(&connector, &config_snapshot).await {
                            Ok(client) => client,
                            Err(err) => {
                                debug!(addr = %client_addr, "periodic ping connect failed: {err}");
                                ClientTransportConnectorPort::invalidate(&connector);
                                ping_id = ping_id.saturating_add(1);
                                continue;
                            }
                        };

                        if let Err(err) = ClientTransportPort::ping(&mut client, req).await {
                            debug!(addr = %client_addr, "periodic ping failed: {err}");
                            ClientTransportConnectorPort::invalidate(&connector);
                        }
                        ping_id = ping_id.saturating_add(1);
                    }
                }
            }

            storage_observer.abort();
            audit.emit(AuditEvent::cold(AuditEventKind::StatsFlowLifecycle(
                StatsFlowLifecycle::Stopped,
            )));
        })
    }
}

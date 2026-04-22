use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::{
    Daemon,
    proc_workers::{DaemonProcWorkerControlPort, DaemonProcWorkerReconfigurePort},
    reload::DaemonReloadPortAdapter,
};
#[cfg(feature = "subscriptions")]
use crate::flows::subscription::{SubscriptionCommandFlow, SubscriptionFlow};
#[cfg(feature = "subscriptions")]
use crate::models::audit::{SubscriptionFlowLifecycle, SubscriptionLifecycle};
use crate::{
    bus::BusRx,
    flows::{
        command::CommandFlow,
        connect::ConnectFlow,
        kernel::KernelFlow,
        notification::NotificationFlow,
        stats::{StatsFlow, WorkerTelemetrySnapshot},
        verdict::{VerdictFlow, VerdictSubmitFlow},
    },
    models::audit::{
        AuditEventKind, AuditLifecycle, AuditSeverity, ClientLifecycle, CommandFlowLifecycle,
        ConnectFlowLifecycle, KernelFlowLifecycle, NotificationFlowLifecycle, StatsFlowLifecycle,
        StatsLifecycle, TaskAction, VerdictFlowLifecycle,
    },
    models::connection_state::ConnectionAttempt,
    services::{
        config::{ConfigService, ProcWorkerReconfigure as ConfigProcWorkerReconfigure},
        dns::DnsService,
        process::ProcessService,
        rule::RuleService,
        stats::StatsService,
    },
    workers::runtime::control::{RuntimeHandles, WorkerControl},
};

impl Daemon {
    pub(super) fn spawn_tasks(
        &self,
        handles: &mut RuntimeHandles,
        rx: BusRx,
        verdict_flow: VerdictFlow,
        notification_flow: NotificationFlow,
    ) {
        info!("starting runtime task set");
        let task_reply_rx = rx.task_reply_rx;
        let alert_rx = rx.alert_rx;
        handles.push_task(
            "notifications",
            self.spawn_notification_task(notification_flow, task_reply_rx, alert_rx),
        );
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::ClientLifecycle(ClientLifecycle::NotificationFlowStarted),
            ));
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::NotificationFlowLifecycle(NotificationFlowLifecycle::Started),
            ));
        debug!("notification task started");

        handles.push_task(
            "connect-attempts",
            self.spawn_connect_attempt_task(
                verdict_flow,
                self.runtime.stats.clone(),
                rx.connect_rx,
            ),
        );
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::ConnectFlowLifecycle(ConnectFlowLifecycle::Started),
            ));
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::VerdictFlowLifecycle(VerdictFlowLifecycle::Started),
            ));
        debug!("connect-attempt task started");

        handles.push_task(
            "kernel-events",
            self.spawn_kernel_task(
                self.runtime.process.clone(),
                self.runtime.dns.clone(),
                self.runtime.stats.clone(),
                rx.kernel_rx,
            ),
        );
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::KernelFlowLifecycle(KernelFlowLifecycle::Started),
            ));
        debug!("kernel-events task started");

        handles.push_task(
            "process-cache-cleanup",
            self.runtime
                .process
                .spawn_cleanup_task(self.runtime.shutdown.clone()),
        );
        debug!("process-cache-cleanup task started");

        handles.push_task(
            "hash-cache-flush",
            self.runtime
                .process
                .spawn_hash_cache_flush_task(self.runtime.shutdown.clone()),
        );
        debug!("hash-cache-flush task started");

        handles.push_task(
            "client-commands",
            CommandFlow::new(
                self.runtime.shutdown.clone(),
                self.runtime.client.clone(),
                self.runtime.config.clone(),
                self.runtime.rules.clone(),
                self.runtime.firewall.clone(),
                self.runtime.process.clone(),
                self.runtime.stats.clone(),
                self.runtime.bus.task_reply_tx.clone(),
                self.runtime.tasks.clone(),
                Arc::new(DaemonProcWorkerReconfigurePort {
                    daemon: self.clone(),
                }),
                Arc::new(DaemonProcWorkerControlPort {
                    proc_workers: self.proc_workers_control(),
                }),
                Arc::new(DaemonReloadPortAdapter {
                    daemon: self.clone(),
                }),
                self.runtime.audit.clone(),
            )
            .spawn(rx.client_cmd_rx),
        );
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::ClientLifecycle(ClientLifecycle::CommandFlowStarted),
            ));
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::CommandFlowLifecycle(CommandFlowLifecycle::Started),
            ));
        debug!("client-command task started");

        handles.push_task(
            "verdict-replies",
            self.spawn_verdict_rpc_task(rx.verdict_rx, self.runtime.stats.clone()),
        );
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::VerdictFlowLifecycle(VerdictFlowLifecycle::RepliesStarted),
            ));
        debug!("verdict-rpc task started");

        handles.push_task(
            "stats",
            self.spawn_stats_flow(
                self.runtime.config.clone(),
                self.runtime.rules.clone(),
                self.runtime.stats.clone(),
                self.runtime.dns.clone(),
            ),
        );
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::StatsLifecycle(StatsLifecycle::FlowStarted),
            ));
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::StatsFlowLifecycle(StatsFlowLifecycle::Started),
            ));
        debug!("stats task started");

        handles.push_task("audit-sink", self.spawn_audit_sink_task());
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::AuditLifecycle(AuditLifecycle::SinkStarted),
            ));
        debug!("audit-sink task started");

        #[cfg(feature = "subscriptions")]
        {
            handles.push_task(
                "subscription-scheduler",
                self.runtime.subscriptions.spawn_scheduler(
                    self.runtime.shutdown.clone(),
                    self.runtime.stats.clone(),
                    self.runtime.rules.clone(),
                    self.runtime.audit.clone(),
                ),
            );
            self.runtime
                .audit
                .emit(crate::models::audit::AuditEvent::cold(
                    AuditEventKind::SubscriptionLifecycle(SubscriptionLifecycle::SchedulerStarted),
                ));
            self.runtime
                .audit
                .emit(crate::models::audit::AuditEvent::cold(
                    AuditEventKind::SubscriptionFlowLifecycle(
                        SubscriptionFlowLifecycle::SchedulerStarted,
                    ),
                ));
            debug!("subscription-scheduler task started");
        }

        #[cfg(feature = "subscriptions")]
        {
            handles.push_task(
                "subscription-flow",
                SubscriptionFlow::new(
                    self.runtime.shutdown.clone(),
                    self.runtime.config.clone(),
                    self.runtime.subscriptions.clone(),
                )
                .spawn(),
            );
            self.runtime
                .audit
                .emit(crate::models::audit::AuditEvent::cold(
                    AuditEventKind::SubscriptionFlowLifecycle(
                        SubscriptionFlowLifecycle::StreamStarted,
                    ),
                ));
            debug!("subscription-flow task started");
        }

        #[cfg(feature = "subscriptions")]
        {
            handles.push_task(
                "subscription-command-flow",
                SubscriptionCommandFlow::new(
                    self.runtime.shutdown.clone(),
                    self.runtime.config.clone(),
                    self.runtime.subscriptions.clone(),
                    self.runtime.audit.clone(),
                )
                .spawn(),
            );
            self.runtime
                .audit
                .emit(crate::models::audit::AuditEvent::cold(
                    AuditEventKind::SubscriptionFlowLifecycle(
                        SubscriptionFlowLifecycle::CommandStreamStarted,
                    ),
                ));
            debug!("subscription-command-flow task started");
        }

        let daemon = self.clone();
        let reconfigure_proc_workers: ConfigProcWorkerReconfigure = Arc::new(move |method| {
            let daemon = daemon.clone();
            Box::pin(async move { daemon.reconfigure_proc_workers(method).await })
        });

        handles.push_worker_control(self.runtime.config.spawn_watch_task(
            self.runtime.shutdown.clone(),
            self.runtime.rules.clone(),
            self.runtime.firewall.clone(),
            self.runtime.stats.clone(),
            self.runtime.alert_buffer.clone(),
            self.runtime.bus.alert_tx.clone(),
            reconfigure_proc_workers,
        ));
        handles.push_worker_control(
            self.runtime
                .rules
                .spawn_watch_task(self.runtime.shutdown.clone()),
        );
        handles.push_worker_control(self.runtime.tasks.spawn_storage_tasks_watch_task(
            self.runtime.shutdown.clone(),
            self.runtime.config.clone(),
            self.runtime.process.clone(),
            self.runtime.bus.task_reply_tx.clone(),
            self.runtime.alert_buffer.clone(),
            self.runtime.bus.alert_tx.clone(),
        ));
        handles.push_worker_control(self.runtime.firewall.spawn_watch_task(
            self.runtime.shutdown.clone(),
            self.runtime.config.clone(),
            self.runtime.rules.clone(),
        ));
        self.runtime
            .audit
            .emit(crate::models::audit::AuditEvent::cold(
                AuditEventKind::TaskAction(TaskAction::RuntimeTasksStarted),
            ));
        debug!("watch tasks started");
    }

    pub(super) fn spawn_notification_task(
        &self,
        flow: NotificationFlow,
        task_reply_rx: tokio::sync::mpsc::Receiver<transport_wire_core::WireNotificationReply>,
        alert_rx: tokio::sync::mpsc::Receiver<crate::models::ui_alert::UiAlert>,
    ) -> JoinHandle<()> {
        let shutdown = self.runtime.shutdown.clone();
        let audit = self.runtime.audit.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                res = flow.run(task_reply_rx, alert_rx) => {
                    if let Err(err) = res {
                        audit.emit(crate::models::audit::AuditEvent::cold(
                            AuditEventKind::NotificationFlowLifecycle(NotificationFlowLifecycle::Failed),
                        ));
                        error!("notification flow failed: {err}");
                    }
                }
            }
        })
    }

    pub(crate) fn spawn_connect_attempt_task(
        &self,
        flow: VerdictFlow,
        stats: StatsService,
        connect_rx: tokio::sync::mpsc::Receiver<ConnectionAttempt>,
    ) -> JoinHandle<()> {
        let verbose_hot_path_audit = self
            .runtime
            .config
            .get_snapshot()
            .audit_sinks
            .verbose_hot_path;
        ConnectFlow::new(
            self.runtime.shutdown.clone(),
            self.runtime.tunables,
            self.runtime.bus.verdict_tx.clone(),
            verbose_hot_path_audit,
        )
        .spawn(flow, stats, self.runtime.audit.clone(), connect_rx)
    }

    pub(crate) fn spawn_kernel_task(
        &self,
        process: ProcessService,
        dns: DnsService,
        stats: StatsService,
        kernel_rx: tokio::sync::mpsc::Receiver<crate::models::kernel_event::KernelEvent>,
    ) -> JoinHandle<()> {
        let verbose_hot_path_audit = self
            .runtime
            .config
            .get_snapshot()
            .audit_sinks
            .verbose_hot_path;
        KernelFlow::new(
            self.runtime.shutdown.clone(),
            self.runtime.tunables,
            self.runtime.kernel_pipeline_counters.clone(),
            verbose_hot_path_audit,
        )
        .spawn(process, dns, stats, self.runtime.audit.clone(), kernel_rx)
    }

    // Test probe — called from smoke tests to inject client commands without running the full gRPC stack.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn spawn_client_command_task(
        &self,
        client_cmd_rx: tokio::sync::mpsc::Receiver<crate::models::command_rpc::ClientCommand>,
    ) -> JoinHandle<()> {
        CommandFlow::new(
            self.runtime.shutdown.clone(),
            self.runtime.client.clone(),
            self.runtime.config.clone(),
            self.runtime.rules.clone(),
            self.runtime.firewall.clone(),
            self.runtime.process.clone(),
            self.runtime.stats.clone(),
            self.runtime.bus.task_reply_tx.clone(),
            self.runtime.tasks.clone(),
            Arc::new(DaemonProcWorkerReconfigurePort {
                daemon: self.clone(),
            }),
            Arc::new(DaemonProcWorkerControlPort {
                proc_workers: self.proc_workers_control(),
            }),
            Arc::new(DaemonReloadPortAdapter {
                daemon: self.clone(),
            }),
            self.runtime.audit.clone(),
        )
        .spawn(client_cmd_rx)
    }

    pub(super) fn spawn_verdict_rpc_task(
        &self,
        verdict_rx: tokio::sync::mpsc::Receiver<crate::models::verdict_rpc::VerdictReply>,
        stats: StatsService,
    ) -> JoinHandle<()> {
        VerdictSubmitFlow::new(self.runtime.shutdown.clone()).spawn(verdict_rx, stats)
    }

    pub(super) fn spawn_stats_flow(
        &self,
        config: ConfigService,
        rules: RuleService,
        stats: StatsService,
        dns: DnsService,
    ) -> JoinHandle<()> {
        let proc_workers = self.proc_workers_control();
        let kernel_pipeline_counters = self.runtime.kernel_pipeline_counters.clone();
        let worker_name = proc_workers.worker_name();
        let worker_snapshot = Arc::new(move || {
            let snapshot = proc_workers.snapshot();
            WorkerTelemetrySnapshot {
                state: snapshot.state.as_str(),
                method: snapshot.method,
                configured_handles: snapshot.configured_handles,
                running_handles: snapshot.running_handles,
                shutdown_requested: snapshot.shutdown_requested,
            }
        });

        let flow = StatsFlow::new(
            self.runtime.shutdown.clone(),
            config,
            self.runtime.client.clone(),
            rules,
            stats,
            {
                let kernel_pipeline_counters = kernel_pipeline_counters.clone();
                Arc::new(move || kernel_pipeline_counters.ingress_stats())
            },
            {
                let kernel_pipeline_counters = kernel_pipeline_counters.clone();
                Arc::new(move || kernel_pipeline_counters.drop_stats())
            },
            worker_name,
            worker_snapshot,
            dns,
            self.runtime.audit.clone(),
        );

        #[cfg(feature = "metrics-export")]
        let flow = {
            use crate::platform::adapters::stats_exporter_prometheus::{
                PROMETHEUS_ADDR_ENV, PrometheusStatsExporter,
            };
            use crate::platform::adapters::stats_exporter_push::{
                MultiStatsExporter, PUSH_BUCKET_ENV, PUSH_FORMAT_ENV, PUSH_GZIP_ENV, PUSH_JOB_ENV,
                PUSH_ORG_ENV, PUSH_TOKEN_ENV, PUSH_URL_ENV, PushConfig, PushFormat,
                PushStatsExporter,
            };
            use crate::platform::ports::stats_exporter_port::StatsExporterPort;

            let mc = &self.runtime.metrics_config;
            let cli = &self.runtime.metrics_cli;

            // §7 resolution: CLI (highest) → env var → JSON config (baseline).

            // ── Prometheus scrape endpoint ───────────────────────────────────────────────
            let prom_addr_str: Option<String> = cli
                .prometheus_addr
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    std::env::var(PROMETHEUS_ADDR_ENV)
                        .ok()
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| mc.prometheus.addr.clone().filter(|s| !s.is_empty()));

            let prom_addr: Option<std::net::SocketAddr> = prom_addr_str.and_then(|s| {
                s.parse::<std::net::SocketAddr>()
                    .map_err(|e| tracing::warn!(addr = %s, "metrics: invalid prometheus addr: {e}"))
                    .ok()
            });

            // Always create the Prometheus exporter so that a SIGHUP hot-reload can
            // attach a new server without needing to restart the stats flow.
            let prom_exp = PrometheusStatsExporter::new();

            let server_ct = prom_addr.map(|addr| {
                let ct = self.runtime.shutdown.child_token();
                prom_exp.clone().spawn_metrics_server(addr, ct.clone());
                ct
            });

            // Store the hot-reload handle so SIGHUP can cancel/rebind as needed.
            *self.runtime.metrics_server.lock().unwrap() = Some(super::MetricsServerSlot {
                exporter: prom_exp.clone(),
                effective_addr: prom_addr,
                server_ct,
            });

            let prom: Option<Arc<dyn StatsExporterPort>> =
                Some(prom_exp as Arc<dyn StatsExporterPort>);

            // ── Push exporter ────────────────────────────────────────────────────────────
            let push_url: Option<String> = cli
                .push_url
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| std::env::var(PUSH_URL_ENV).ok().filter(|s| !s.is_empty()))
                .or_else(|| mc.push.url.clone().filter(|s| !s.is_empty()));

            let push: Option<Arc<dyn StatsExporterPort>> = push_url.map(|url| {
                // Format: CLI → env var → JSON (non-default).
                let format_str: Option<String> = cli
                    .push_format
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        std::env::var(PUSH_FORMAT_ENV)
                            .ok()
                            .filter(|s| !s.is_empty())
                    })
                    .or_else(|| {
                        if !mc.push.format.is_default() {
                            Some(mc.push.format.as_str().to_string())
                        } else {
                            None
                        }
                    });
                let format = match format_str.as_deref().unwrap_or("").to_lowercase().as_str() {
                    "influxdb" | "influx" => PushFormat::InfluxDb,
                    "pushgateway-proto" | "proto" => PushFormat::PushgatewayProto,
                    _ => PushFormat::Pushgateway,
                };
                // Job label: CLI → env var → JSON.
                let job = cli
                    .push_job
                    .clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| std::env::var(PUSH_JOB_ENV).ok().filter(|s| !s.is_empty()))
                    .or_else(|| mc.push.job.clone().filter(|s| !s.is_empty()))
                    .unwrap_or_else(|| "opensnitchd".to_string());
                // Auth token: CLI → env var → JSON.
                let token = cli
                    .push_token
                    .clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| std::env::var(PUSH_TOKEN_ENV).ok().filter(|s| !s.is_empty()))
                    .or_else(|| mc.push.token.clone().filter(|s| !s.is_empty()));
                // Gzip: CLI flag (highest) → env var → JSON config.
                let gzip = cli.push_gzip.unwrap_or(false)
                    || std::env::var(PUSH_GZIP_ENV)
                        .ok()
                        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                        .unwrap_or(false)
                    || mc.push.gzip;
                // InfluxDB-specific: env var → JSON.
                let bucket = std::env::var(PUSH_BUCKET_ENV)
                    .ok()
                    .filter(|s| !s.is_empty())
                    .or_else(|| mc.push.bucket.clone().filter(|s| !s.is_empty()))
                    .unwrap_or_else(|| "opensnitch".to_string());
                let org = std::env::var(PUSH_ORG_ENV)
                    .ok()
                    .filter(|s| !s.is_empty())
                    .or_else(|| mc.push.org.clone().filter(|s| !s.is_empty()))
                    .unwrap_or_default();
                PushStatsExporter::new(
                    PushConfig {
                        url,
                        format,
                        job,
                        token,
                        gzip,
                        bucket,
                        org,
                    },
                    self.runtime.shutdown.clone(),
                ) as Arc<dyn StatsExporterPort>
            });

            match (prom, push) {
                (Some(p), Some(q)) => flow.with_stats_exporter(MultiStatsExporter::new(vec![p, q])),
                (Some(p), None) => flow.with_stats_exporter(p),
                (None, Some(q)) => flow.with_stats_exporter(q),
                (None, None) => flow,
            }
        };

        flow.spawn()
    }

    pub(super) fn spawn_audit_sink_task(&self) -> JoinHandle<()> {
        let shutdown = self.runtime.shutdown.clone();
        let mut rx = self.runtime.audit.subscribe();
        let sinks = self.runtime.audit_sinks.clone();
        let audit = self.runtime.audit.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        audit.emit(crate::models::audit::AuditEvent::cold(
                            AuditEventKind::AuditLifecycle(AuditLifecycle::Stopped),
                        ));
                        break;
                    }
                    next = rx.recv() => {
                        match next {
                            Ok(event) => {
                                // Dispatch to file / syslog sinks (fail-open).
                                sinks.dispatch(&event);
                                // Log-line sink: emit as tracing events with span context.
                                if !sinks.log_lines_enabled_for(event.severity) {
                                    continue;
                                }
                                let _span = tracing::info_span!("audit", family = %event.family).entered();
                                match event.severity {
                                    AuditSeverity::Error => tracing::error!(kind = %event.kind),
                                    AuditSeverity::Warning => tracing::warn!(kind = %event.kind),
                                    AuditSeverity::Info => tracing::info!(kind = %event.kind),
                                    AuditSeverity::Debug => tracing::debug!(kind = %event.kind),
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(skipped, "audit sink lagged behind audit stream");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        })
    }
}

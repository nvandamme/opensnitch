use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{Daemon, DaemonRuntime, ProcWorkersRuntime};
use crate::{
    bus::{BusCaps, BusRx, BusState},
    models::audit::{
        AuditEvent, AuditEventKind, AuditLifecycle, ClientLifecycle, ConfigLifecycle,
        ConnectionLifecycle, DnsLifecycle, FirewallLifecycle, ProcessLifecycle, RuleLifecycle,
        StatsLifecycle, StorageLifecycle, SubscriptionLifecycle, TaskLifecycle,
    },
    services::{
        client::{self, ClientService},
        config::ConfigService,
        connection::ConnectionService,
        dns::DnsService,
        firewall::{FirewallService, firewall_backend_name},
        process::ProcessService,
        rule::RuleService,
        stats::StatsService,
        storage::StorageService,
        subscription::SubscriptionService,
        task,
    },
    tunables::RuntimeTunables,
};

impl Daemon {
    pub async fn bootstrap(mut cli: crate::CliOverrides) -> Result<(Self, BusRx)> {
        let (bus, rx) = BusState::build_with_caps(BusCaps {
            connect: 1024,
            kernel: 512,
            client_cmd: 256,
            verdict: 1024,
            task_reply: 256,
            alert: 1024,
        });
        crate::utils::daemon_guard::ensure_no_competing_daemon_instances()?;
        let mut config = crate::config::Config::load_from_default_locations_with_override(
            cli.config_file.as_deref(),
        )?
        .with_client_addr_override(cli.ui_socket.as_deref())
        .with_auth_mode_override(cli.auth_mode.as_deref())
        .with_rules_path_override(cli.rules_path.as_deref());
        // §7: apply env var + CLI overrides for audit sinks
        // Priority: CLI flags > env vars > config file SinkFile/SinkSyslog/SinkLogLines
        {
            let s = &mut config.audit_sinks;
            if let Ok(v) = std::env::var("OPENSNITCH_AUDIT_SINK_FILE") {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    s.sink_file = Some(std::path::PathBuf::from(v));
                }
            }
            if std::env::var("OPENSNITCH_AUDIT_SINK_SYSLOG").as_deref() == Ok("1") {
                s.sink_syslog = true;
            }
            if std::env::var("OPENSNITCH_AUDIT_SINK_LOG").as_deref() == Ok("1") {
                s.sink_log_lines = true;
            }
            if std::env::var("OPENSNITCH_AUDIT_VERBOSE_HOT_PATH").as_deref() == Ok("1") {
                s.verbose_hot_path = true;
            }
            if let Some(f) = cli.audit.sink_file.take() {
                s.sink_file = Some(f);
            }
            if let Some(v) = cli.audit.sink_syslog {
                s.sink_syslog = v;
            }
            if let Some(v) = cli.audit.sink_log_lines {
                s.sink_log_lines = v;
            }
            if let Some(v) = cli.audit.verbose_hot_path {
                s.verbose_hot_path = v;
            }
        }
        crate::utils::kernel_caps::log(&crate::utils::kernel_caps::run());
        if let Some(status) = crate::tunables::RuntimeTunables::maybe_autotune_on_startup() {
            info!(status = %status, "daemon bootstrap: startup autotune");
        }
        let (tunables, tunables_source) = RuntimeTunables::load_effective();
        tunables.publish_global();
        info!(
            addr = %config.client_addr,
            ?config.default_action,
            ?config.proc_monitor_method,
            ?config.firewall_backend,
            "daemon bootstrap: loaded config"
        );
        match config.auth_mode {
            crate::config::AuthMode::Legacy => {
                warn!(
                    auth_mode = config.auth_mode.as_name(),
                    "daemon bootstrap: legacy client authorization is enabled; connected clients retain full privileged control"
                );
            }
            crate::config::AuthMode::LocalOnly => {
                let local_policy_configured = config.local_control_allowed_principals.is_some()
                    || config.local_control_allowed_group_gids.is_some();
                if local_policy_configured {
                    warn!(
                        auth_mode = config.auth_mode.as_name(),
                        "daemon bootstrap: local-only authorization is active; remote privileged control is denied and non-root local payloads must prove owner scope"
                    );
                } else {
                    warn!(
                        auth_mode = config.auth_mode.as_name(),
                        "daemon bootstrap: local-only authorization is active without an explicit principal/group policy; root-only fallback will be enforced"
                    );
                }
            }
            crate::config::AuthMode::LocalRemoteCapabilities => {
                let remote_bindings_configured = config
                    .remote_principal_bindings
                    .as_ref()
                    .is_some_and(|bindings| !bindings.is_empty());
                if remote_bindings_configured {
                    warn!(
                        auth_mode = config.auth_mode.as_name(),
                        "daemon bootstrap: local+remote authorization is active; remote privileged control requires TLS-authenticated client bindings and explicit capability grants"
                    );
                } else {
                    warn!(
                        auth_mode = config.auth_mode.as_name(),
                        "daemon bootstrap: local+remote is configured without any remote principal bindings; remote privileged control currently falls back to local-only behavior"
                    );
                }
            }
        }
        info!(
            source = %tunables_source,
            max_concurrent_connect_attempts = tunables.max_concurrent_connect_attempts,
            connect_worker_queue_capacity = tunables.connect_worker_queue_capacity,
            connect_dispatch_batch_size = tunables.connect_dispatch_batch_size,
            kernel_ingress_dispatch_batch_size = tunables.kernel_ingress_dispatch_batch_size,
            kernel_dns_dispatch_batch_size = tunables.kernel_dns_dispatch_batch_size,
            kernel_process_dispatch_batch_size = tunables.kernel_process_dispatch_batch_size,
            kernel_firewall_dispatch_batch_size = tunables.kernel_firewall_dispatch_batch_size,
            kernel_dns_queue_capacity = tunables.kernel_dns_queue_capacity,
            kernel_process_queue_capacity = tunables.kernel_process_queue_capacity,
            kernel_firewall_queue_capacity = tunables.kernel_firewall_queue_capacity,
            nfqueue_overload_policy = tunables.nfqueue_overload_policy.as_str(),
            netlink_fallback_retry_delay_ms = tunables.netlink_fallback_retry_delay_ms,
            netlink_recovery_poll_interval_ms = tunables.netlink_recovery_poll_interval_ms,
            ebpf_map_prune_enabled = tunables.ebpf_map_prune_enabled,
            ebpf_map_prune_threshold_percent = tunables.ebpf_map_prune_threshold_percent,
            ebpf_map_prune_target_percent = tunables.ebpf_map_prune_target_percent,
            dns_lru_cache_capacity = tunables.dns_lru_cache_capacity,
            process_info_cache_capacity = tunables.process_info_cache_capacity,
            pid_inode_cache_capacity = tunables.pid_inode_cache_capacity,
            pid_inode_key_cache_capacity = tunables.pid_inode_key_cache_capacity,
            stats_event_ring_capacity = tunables.stats_event_ring_capacity,
            alert_overflow_ring_capacity = tunables.alert_overflow_ring_capacity,
            audit_ring_capacity = tunables.audit_ring_capacity,
            "daemon bootstrap: effective runtime tunables"
        );
        DnsService::configure_cache_capacity(tunables.dns_lru_cache_capacity);
        ProcessService::configure_cache_capacity(tunables.process_info_cache_capacity);
        ConnectionService::configure_pid_owner_cache_capacities(
            tunables.pid_inode_cache_capacity,
            tunables.pid_inode_key_cache_capacity,
        );
        StatsService::configure_event_ring_capacity(tunables.stats_event_ring_capacity);
        let config_service = ConfigService::new(config.clone());
        let client_service = ClientService::default();
        let alert_buffer =
            client::AlertBuffer::with_capacity(tunables.alert_overflow_ring_capacity);
        let mut rules = RuleService::default();
        rules.set_network_aliases_path(config.network_aliases_path.clone());
        rules.load_path(&config.rules_path).await?;
        info!(path = %config.rules_path.display(), "daemon bootstrap: initial rules loaded");
        let firewall = FirewallService::new(&config)?;
        let firewall_rules_applied = if let Err(err) = firewall.ensure_rules().await {
            warn!(
                backend = firewall_backend_name(config.firewall_backend),
                "firewall bootstrap skipped: {err}"
            );
            false
        } else {
            info!(
                backend = firewall_backend_name(config.firewall_backend),
                "daemon bootstrap: firewall ensured"
            );
            true
        };

        let process = ProcessService::default();
        let dns = DnsService::default();
        let connections = ConnectionService::new(process.clone(), dns.clone());
        let subscriptions = SubscriptionService::with_system_defaults();

        // §7: load JSON config layer for metrics export (fail-open: absent file → defaults).
        let metrics_config =
            crate::models::metrics_config::MetricsConfig::load_sibling(&config.config_path)
                .unwrap_or_else(|e| {
                    warn!("metrics.json could not be loaded, using defaults: {e}");
                    Default::default()
                });
        let metrics_cli = cli.metrics;
        let audit = crate::services::audit::AuditService::new(tunables.audit_ring_capacity);
        let audit_sinks = crate::services::audit::AuditSinks::from_config(&config.audit_sinks);

        let daemon = Self {
            runtime: Arc::new(DaemonRuntime {
                config: config_service,
                client: client_service,
                nfqueue_num: config.firewall_queue_num,
                default_action: config.default_action,
                audit_socket_path: config.audit_socket_path.clone(),
                proc_workers: Arc::new(std::sync::Mutex::new(ProcWorkersRuntime {
                    current_method: config.proc_monitor_method,
                    shutdown: CancellationToken::new(),
                    handles: Vec::new(),
                })),
                bus,
                alert_buffer,
                kernel_pipeline_counters: Arc::new(crate::daemon::KernelPipelineCounters::default()),
                rules,
                connections,
                process,
                dns,
                stats: StatsService::default(),
                firewall,
                subscriptions,
                tasks: task::TaskService,
                tunables,
                shutdown: CancellationToken::new(),
                metrics_config,
                metrics_cli,
                audit,
                audit_sinks,
                #[cfg(feature = "metrics-export")]
                metrics_server: std::sync::Mutex::new(None),
            }),
        };

        StorageService::install_global_audit(
            daemon.runtime.audit.clone(),
            config.audit_sinks.verbose_hot_path,
        );

        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ConfigLifecycle(
                ConfigLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ConfigLifecycle(
                ConfigLifecycle::Started,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ClientLifecycle(
                ClientLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::RuleLifecycle(
                RuleLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::RuleLifecycle(
                RuleLifecycle::Started,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::FirewallLifecycle(
                FirewallLifecycle::Initialized,
            )));
        if firewall_rules_applied {
            daemon
                .runtime
                .audit
                .emit(AuditEvent::cold(AuditEventKind::FirewallLifecycle(
                    FirewallLifecycle::Started,
                )));
        } else {
            daemon
                .runtime
                .audit
                .emit(AuditEvent::cold(AuditEventKind::FirewallAction(
                    crate::models::audit::FirewallAction::EnsureRulesSkipped,
                )));
        }
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ProcessLifecycle(
                ProcessLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::DnsLifecycle(
                DnsLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::ConnectionLifecycle(
                ConnectionLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::SubscriptionLifecycle(
                SubscriptionLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::StatsLifecycle(
                StatsLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::TaskLifecycle(
                TaskLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::AuditLifecycle(
                AuditLifecycle::Initialized,
            )));
        daemon
            .runtime
            .audit
            .emit(AuditEvent::cold(AuditEventKind::StorageLifecycle(
                StorageLifecycle::Initialized,
            )));

        let list_rule_paths = daemon.runtime.rules.list_rule_data_paths();
        daemon.runtime.stats.update_subscription_stats(
            daemon
                .runtime
                .subscriptions
                .subscription_stats_with_rules(&list_rule_paths),
        );

        daemon.runtime.stats.apply_config(config.stats);

        Ok((daemon, rx))
    }
}

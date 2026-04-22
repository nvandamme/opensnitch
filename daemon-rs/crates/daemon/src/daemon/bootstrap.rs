use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{Daemon, DaemonRuntime, ProcWorkersRuntime};
use crate::{
    bus::{BusCaps, BusRx, BusState},
    services::{
        client::{self, ClientService},
        config::ConfigService,
        connection::ConnectionService,
        dns::DnsService,
        firewall::{FirewallService, firewall_backend_name},
        process::ProcessService,
        rule::RuleService,
        stats::StatsService,
        subscription::SubscriptionService,
        task,
    },
    tunables::RuntimeTunables,
};

impl Daemon {
    pub async fn bootstrap(client_addr: Option<&str>) -> Result<(Self, BusRx)> {
        let (bus, rx) = BusState::build_with_caps(BusCaps {
            connect: 1024,
            kernel: 512,
            client_cmd: 256,
            verdict: 1024,
            task_reply: 256,
            alert: 1024,
        });
        crate::utils::daemon_guard::ensure_no_competing_daemon_instances()?;
        let config = crate::config::Config::load_from_default_locations()?
            .with_client_addr_override(client_addr);
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
        let alert_buffer = client::AlertBuffer::with_capacity(tunables.alert_overflow_ring_capacity);
        let rules = RuleService::default();
        rules.load_path(&config.rules_path).await?;
        info!(path = %config.rules_path.display(), "daemon bootstrap: initial rules loaded");
        let firewall = FirewallService::new(&config)?;
        if let Err(err) = firewall.ensure_rules().await {
            warn!(
                backend = firewall_backend_name(config.firewall_backend),
                "firewall bootstrap skipped: {err}"
            );
        } else {
            info!(
                backend = firewall_backend_name(config.firewall_backend),
                "daemon bootstrap: firewall ensured"
            );
        }

        let process = ProcessService::default();
        let dns = DnsService::default();
        let connections = ConnectionService::new(process.clone(), dns.clone());
        let subscriptions = SubscriptionService::with_system_defaults();

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
            }),
        };

        let (sub_total, sub_ready, sub_error) = daemon.runtime.subscriptions.counts();
        daemon
            .runtime
            .stats
            .update_subscription_counts(sub_total, sub_ready, sub_error);

        daemon.runtime.stats.apply_config(config.stats);

        Ok((daemon, rx))
    }
}

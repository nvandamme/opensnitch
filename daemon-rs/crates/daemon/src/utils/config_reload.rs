pub(crate) use crate::models::config::reload::{
    RuntimeApplyMessageContext, RuntimeApplyPolicy, RuntimeApplyReport, RuntimeApplyStage,
    RuntimeApplyStageMessages,
};
use crate::platform::conman::conntrack::{flush_conntrack_expect, flush_conntrack_table};

pub(crate) fn apply_runtime_core(
    updated: &crate::config::Config,
    stats: &crate::services::stats::StatsService,
) {
    refresh_runtime_reloadable_singletons();
    crate::platform::nfqueue::state::NfqueueRuntimeState::set_default_action(
        updated.default_action,
    );
    stats.apply_config(updated.stats);
    apply_gc_percent(updated.gc_percent);
}

fn refresh_runtime_reloadable_singletons() {
    let (_, tunables_source) = crate::tunables::RuntimeTunables::reload_global();
    tracing::debug!(
        source = %tunables_source,
        "reloaded runtime tunables singleton"
    );

    crate::services::stats::StatsService::reload_daemon_version_from_env();
    crate::platform::netlink::ifaces::NetIfaceAdapter::clear_interface_name_cache();
    crate::services::connection::ConnectionService::reset_pid_owner_caches();
    let _ = crate::services::storage::StorageService::reload_global();
    tracing::debug!("reloaded storage runtime singleton");
}

pub(crate) fn runtime_apply_stage_messages(
    context: RuntimeApplyMessageContext,
    stage: RuntimeApplyStage,
) -> RuntimeApplyStageMessages {
    match context {
        RuntimeApplyMessageContext::ConfigCommand => match stage {
            RuntimeApplyStage::Logging => RuntimeApplyStageMessages {
                log: "failed to apply runtime logging config after config change",
                external: "failed to apply runtime log level after config change",
            },
            RuntimeApplyStage::Rules => RuntimeApplyStageMessages {
                log: "failed to reload rules after config change",
                external: "failed to reload rules after config change",
            },
            RuntimeApplyStage::Firewall => RuntimeApplyStageMessages {
                log: "failed to reconcile firewall after config change",
                external: "failed to reconcile firewall after config change",
            },
        },
        RuntimeApplyMessageContext::ConfigWatch => match stage {
            RuntimeApplyStage::Logging => RuntimeApplyStageMessages {
                log: "failed to apply runtime logging config after config file change",
                external: "failed to apply runtime logging config after config file change",
            },
            RuntimeApplyStage::Rules => RuntimeApplyStageMessages {
                log: "failed to reload rules after config file change",
                external: "failed to reload rules after config file change",
            },
            RuntimeApplyStage::Firewall => RuntimeApplyStageMessages {
                log: "failed to reconcile firewall after config file change",
                external: "failed to reconcile firewall after config file change",
            },
        },
        RuntimeApplyMessageContext::Sighup => match stage {
            RuntimeApplyStage::Logging => RuntimeApplyStageMessages {
                log: "failed to apply logging config after SIGHUP reload",
                external: "SIGHUP reload failed while applying logging config",
            },
            RuntimeApplyStage::Rules => RuntimeApplyStageMessages {
                log: "failed to reload rules after SIGHUP",
                external: "SIGHUP reload failed while reloading rules",
            },
            RuntimeApplyStage::Firewall => RuntimeApplyStageMessages {
                log: "failed to reconcile firewall after SIGHUP",
                external: "SIGHUP reload failed while reconciling firewall",
            },
        },
    }
}

impl RuntimeApplyReport {
    pub(crate) fn into_stage_errors(self) -> Vec<(RuntimeApplyStage, anyhow::Error)> {
        let mut out = Vec::new();
        if let Some(err) = self.logging_error {
            out.push((RuntimeApplyStage::Logging, err));
        }
        if let Some(err) = self.rules_error {
            out.push((RuntimeApplyStage::Rules, err));
        }
        if let Some(err) = self.firewall_error {
            out.push((RuntimeApplyStage::Firewall, err));
        }
        out
    }
}

pub(crate) async fn apply_runtime_config_services(
    updated: &crate::config::Config,
    rules: &crate::services::rule::RuleService,
    firewall: &crate::services::firewall::FirewallService,
    policy: RuntimeApplyPolicy,
    reload_firewall: bool,
) -> RuntimeApplyReport {
    let logging_error = crate::logging::LoggingState::apply_config(updated).err();

    let rules_error = rules.load_path(&updated.rules_path).await.err();

    let firewall_error = if !reload_firewall {
        None
    } else if matches!(policy, RuntimeApplyPolicy::StopAfterRulesError) && rules_error.is_some() {
        None
    } else {
        firewall.reconcile_from_config(updated).await.err()
    };

    RuntimeApplyReport {
        logging_error,
        rules_error,
        firewall_error,
    }
}

pub(crate) fn has_proc_runtime_change(
    previous: &crate::config::Config,
    updated: &crate::config::Config,
) -> bool {
    previous.proc_monitor_method != updated.proc_monitor_method
        || previous.audit_socket_path != updated.audit_socket_path
}

pub(crate) fn has_firewall_runtime_change(
    previous: &crate::config::Config,
    updated: &crate::config::Config,
    include_monitor_interval: bool,
) -> bool {
    crate::services::firewall::firewall_backend_name(previous.firewall_backend)
        != crate::services::firewall::firewall_backend_name(updated.firewall_backend)
        || previous.firewall_persistence_mode != updated.firewall_persistence_mode
        || previous.firewall_config_path != updated.firewall_config_path
        || previous.firewall_queue_num != updated.firewall_queue_num
        || previous.firewall_queue_bypass != updated.firewall_queue_bypass
        || (include_monitor_interval
            && previous.firewall_monitor_interval != updated.firewall_monitor_interval)
}

pub(crate) fn log_config_delta(
    previous: &crate::config::Config,
    updated: &crate::config::Config,
    include_firewall_monitor_interval: bool,
) {
    if previous.log_file == updated.log_file {
        tracing::debug!("[config] config.server.logfile not changed");
    } else {
        let value = updated
            .log_file
            .as_ref()
            .map(|v| v.display().to_string())
            .unwrap_or_else(|| "/dev/stdout".to_string());
        tracing::debug!("[config] using config.server.logfile: {value}");
    }

    if previous.loggers == updated.loggers {
        tracing::debug!("[config] config.server.loggers not changed");
    } else {
        tracing::debug!(
            old = previous.loggers.len(),
            new = updated.loggers.len(),
            "[config] reloading config.server.loggers"
        );
    }

    if previous.stats.max_events == updated.stats.max_events
        && previous.stats.max_stats == updated.stats.max_stats
        && previous.stats.workers == updated.stats.workers
    {
        tracing::debug!("[config] config.stats not changed");
    } else {
        tracing::debug!("[config] reloading config.stats");
    }

    if previous.client_addr != updated.client_addr {
        tracing::debug!(
            "[config] using new config.server.address: {} -> {}",
            previous.client_addr,
            updated.client_addr
        );
        let reconnect = previous.client_addr != updated.client_addr;
        let connect = !updated.client_addr.is_empty();
        if previous.client_addr.is_empty() {
            let target_addr = updated
                .client_addr
                .strip_prefix("unix:")
                .unwrap_or(updated.client_addr.as_str());
            tracing::debug!(
                "[config] previous address was empty, connected: false, connecting to {}",
                target_addr
            );
        }
        tracing::debug!(
            "[config] server.address old: {}, new: {}, reconnect: {}, connect: {}",
            previous.client_addr,
            updated.client_addr,
            reconnect,
            connect
        );
        tracing::debug!(
            "[config] config.server.address.* changed, disconnecting from {}",
            previous.client_addr
        );
        if connect {
            let target_addr = updated
                .client_addr
                .strip_prefix("unix:")
                .unwrap_or(updated.client_addr.as_str());
            tracing::debug!(
                "[config] config.server. changed, connecting to {}",
                target_addr
            );
        }
    } else {
        tracing::debug!("[config] config.server.address.* not changed");
    }

    if previous.rules_enable_checksums == updated.rules_enable_checksums {
        tracing::debug!(
            "SetComputeChecksums(), no changes ({}, {})",
            previous.rules_enable_checksums,
            updated.rules_enable_checksums
        );
    } else if updated.rules_enable_checksums {
        tracing::debug!("SetComputeChecksums() enabled, recomputing cached checksums");
    } else {
        tracing::debug!("SetComputeChecksums() disabled, deleting saved checksums");
    }
    tracing::debug!(
        "[rules loader] EnableChecksums: {}",
        updated.rules_enable_checksums
    );

    if previous.gc_percent == updated.gc_percent {
        tracing::debug!("[config] config.Internal.GCPercent not changed");
    } else {
        tracing::debug!(
            old = ?previous.gc_percent,
            new = ?updated.gc_percent,
            "[config] reloading config.Internal.GCPercent"
        );
    }

    if previous.rules_path != updated.rules_path {
        tracing::debug!(
            "[config] reloading config.rules.path, old: <{}> new: <{}>",
            previous.rules_path.display(),
            updated.rules_path.display()
        );
    } else {
        tracing::debug!("[config] config.rules.path not changed");
    }

    if previous.proc_monitor_method != updated.proc_monitor_method {
        tracing::debug!(
            "[config] reloading config.ProcMonMethod, old: {} -> new: {}",
            previous.proc_monitor_method,
            updated.proc_monitor_method
        );
    } else {
        tracing::debug!("[config] config.ProcMonMethod not changed");
    }

    if previous.audit_socket_path != updated.audit_socket_path {
        tracing::debug!("[config] reloading config.Audit");
    } else {
        tracing::debug!("[config] config.Audit not changed");
    }

    if previous.ebpf_modules_path == updated.ebpf_modules_path {
        tracing::debug!("[config] config.Ebpf.ModulesPath not changed");
    } else {
        tracing::debug!(
            "[config] reloading config.Ebpf.ModulesPath, old: {} -> new: {}",
            previous.ebpf_modules_path.display(),
            updated.ebpf_modules_path.display()
        );
    }

    if previous.proc_monitor_method == updated.proc_monitor_method
        && previous.audit_socket_path == updated.audit_socket_path
        && previous.ebpf_modules_path == updated.ebpf_modules_path
    {
        tracing::debug!("[config] config.procmon not changed");
    }

    let firewall_changed =
        has_firewall_runtime_change(previous, updated, include_firewall_monitor_interval);

    if firewall_changed {
        tracing::debug!("[config] reloading config.firewall");
    } else {
        tracing::debug!("[config] config.firewall not changed");
    }

    if previous.tasks_config_path != updated.tasks_config_path {
        tracing::debug!(
            "[tasks] Loader.Load() config file: {}",
            updated.tasks_config_path.display()
        );
    } else {
        tracing::debug!("[config] config.TasksOptions not changed");
    }
}

pub(crate) fn apply_gc_percent(gc_percent: Option<i32>) {
    if let Some(gc_percent) = gc_percent {
        tracing::debug!(
            gc_percent,
            "config.Internal.GCPercent requested; Rust runtime has no Go-style GC percent knob, keeping setting for parity metadata only"
        );
    }
}

pub(crate) async fn flush_established_connections() {
    tracing::debug!("[config] flushing established connections");

    if let Err(err) = flush_conntrack_table().await {
        tracing::error!("error flushing ConntrackTable {err}");
    }

    if let Err(err) = flush_conntrack_expect().await {
        tracing::error!("error flusing ConntrackExpectTable {err}");
    }
}

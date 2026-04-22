use tokio::process::Command;

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
            "[config] reloading config.ProcMonMethod, old: {:?} -> new: {:?}",
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

    let firewall_changed = previous.firewall_backend.as_str() != updated.firewall_backend.as_str()
        || previous.firewall_config_path != updated.firewall_config_path
        || previous.firewall_queue_num != updated.firewall_queue_num
        || previous.firewall_queue_bypass != updated.firewall_queue_bypass
        || (include_firewall_monitor_interval
            && previous.firewall_monitor_interval != updated.firewall_monitor_interval);

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

    let table = Command::new("conntrack").args(["-F"]).output().await;
    match table {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            tracing::error!(
                "error flushing ConntrackTable {}",
                if err.is_empty() {
                    "failed"
                } else {
                    err.as_str()
                }
            );
        }
        Err(err) => tracing::error!("error flushing ConntrackTable {err}"),
    }

    let expect = Command::new("conntrack")
        .args(["-F", "expect"])
        .output()
        .await;
    match expect {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            tracing::error!(
                "error flusing ConntrackExpectTable {}",
                if err.is_empty() {
                    "failed"
                } else {
                    err.as_str()
                }
            );
        }
        Err(err) => tracing::error!("error flusing ConntrackExpectTable {err}"),
    }
}

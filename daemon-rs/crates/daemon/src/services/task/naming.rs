use serde_json::Value;

use crate::utils::json_value;
use crate::utils::name_parsing::{AliasRule, canonicalize_alias, suffix_after_any_prefix};

pub(crate) const TASK_PID_MONITOR: &str = "pid-monitor";
pub(crate) const TASK_NODE_MONITOR: &str = "node-monitor";
pub(crate) const TASK_SOCKETS_MONITOR: &str = "sockets-monitor";
pub(crate) const TASK_LOOPER: &str = "looper";
pub(crate) const TASK_DOWNLOADER: &str = "downloader";
pub(crate) const TASK_IOC_SCANNER: &str = "ioc-scanner";

const RUNTIME_TASK_NAMES: &[&str] = &[TASK_PID_MONITOR, TASK_NODE_MONITOR, TASK_SOCKETS_MONITOR];
const STORAGE_TASK_NAMES: &[&str] = &[TASK_LOOPER, TASK_DOWNLOADER, TASK_IOC_SCANNER];
const INTERVAL_VALIDATED_TASK_NAMES: &[&str] = &[
    TASK_PID_MONITOR,
    TASK_NODE_MONITOR,
    TASK_SOCKETS_MONITOR,
    TASK_LOOPER,
    TASK_DOWNLOADER,
    TASK_IOC_SCANNER,
];

pub(crate) fn build_task_key(task_name: &str, data: &Value) -> String {
    let normalized_name = normalized_task_name(task_name);
    match normalized_name.as_str() {
        TASK_PID_MONITOR => format!(
            "{TASK_PID_MONITOR}:{}",
            data_or_suffix(data, "pid", task_name, TASK_PID_MONITOR).unwrap_or_default()
        ),
        TASK_NODE_MONITOR => format!(
            "{TASK_NODE_MONITOR}:{}",
            data_or_suffix(data, "node", task_name, TASK_NODE_MONITOR)
                .unwrap_or_else(|| "default".to_string())
        ),
        TASK_SOCKETS_MONITOR => TASK_SOCKETS_MONITOR.to_string(),
        _ => normalized_name,
    }
}

pub(crate) fn normalized_task_name(name: &str) -> String {
    const RULES: &[AliasRule<'_>] = &[
        AliasRule {
            canonical: TASK_PID_MONITOR,
            exact: &["pidmonitor", TASK_PID_MONITOR],
            prefixes: &["pidmonitor-", "pid-monitor-"],
        },
        AliasRule {
            canonical: TASK_NODE_MONITOR,
            exact: &["nodemonitor", TASK_NODE_MONITOR],
            prefixes: &["nodemonitor-", "node-monitor-"],
        },
        AliasRule {
            canonical: TASK_SOCKETS_MONITOR,
            exact: &["socketsmonitor", TASK_SOCKETS_MONITOR, "netstat"],
            prefixes: &["socketsmonitor-", "sockets-monitor-", "netstat-"],
        },
        AliasRule {
            canonical: TASK_LOOPER,
            exact: &["looptask", TASK_LOOPER],
            prefixes: &["looptask-", "looper-"],
        },
        AliasRule {
            canonical: TASK_IOC_SCANNER,
            exact: &[TASK_IOC_SCANNER, "iocscanner"],
            prefixes: &["ioc-scanner-", "iocscanner-"],
        },
        AliasRule {
            canonical: TASK_DOWNLOADER,
            exact: &[TASK_DOWNLOADER],
            prefixes: &["downloader-"],
        },
    ];

    canonicalize_alias(name, RULES)
}

fn canonical_task_name_in_set(canonical_name: &str, supported: &[&str]) -> bool {
    supported.contains(&canonical_name)
}

pub(crate) fn is_runtime_canonical_task_name(canonical_name: &str) -> bool {
    canonical_task_name_in_set(canonical_name, RUNTIME_TASK_NAMES)
}

pub(crate) fn is_storage_canonical_task_name(canonical_name: &str) -> bool {
    canonical_task_name_in_set(canonical_name, STORAGE_TASK_NAMES)
}

pub(crate) fn canonical_task_name_supports_interval(canonical_name: &str) -> bool {
    canonical_task_name_in_set(canonical_name, INTERVAL_VALIDATED_TASK_NAMES)
}

pub(crate) fn task_instance_suffix(task_name: &str, canonical_name: &str) -> Option<String> {
    let prefixes: &[&str] = match canonical_name {
        TASK_PID_MONITOR => &["pid-monitor-", "pidmonitor-"],
        TASK_NODE_MONITOR => &["node-monitor-", "nodemonitor-"],
        _ => &[],
    };

    suffix_after_any_prefix(task_name, prefixes)
}

pub(crate) fn data_or_suffix(
    data: &Value,
    key: &str,
    task_name: &str,
    canonical_name: &str,
) -> Option<String> {
    json_value::field_string_or_u64(data, key)
        .or_else(|| task_instance_suffix(task_name, canonical_name))
}

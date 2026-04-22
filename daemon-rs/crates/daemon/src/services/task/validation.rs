use serde_json::Value;

use crate::services::task::naming as task_runtime_naming;
use crate::utils::duration_parse::{TASK_INTERVAL_OPTIONS, parse_human_duration};
use crate::utils::json_value;
use crate::utils::proc_fs::proc_pid_exists;

pub(crate) fn validate_task_start_input(task_name: &str, data: &Value) -> Result<(), String> {
    let normalized = task_runtime_naming::normalized_task_name(task_name);

    if task_runtime_naming::canonical_task_name_supports_interval(normalized.as_str())
        && let Some(raw_interval) = json_value::field_string_or_u64(data, "interval")
        && !raw_interval.trim().is_empty()
        && parse_human_duration(raw_interval.trim(), TASK_INTERVAL_OPTIONS).is_none()
    {
        return Err(format!("invalid interval for {normalized}"));
    }

    if normalized != task_runtime_naming::TASK_PID_MONITOR {
        if normalized == task_runtime_naming::TASK_NODE_MONITOR {
            if task_runtime_naming::data_or_suffix(
                data,
                "node",
                task_name,
                task_runtime_naming::TASK_NODE_MONITOR,
            )
            .is_none()
            {
                return Err("invalid node for node-monitor".to_string());
            }
            return Ok(());
        }

        if normalized == task_runtime_naming::TASK_SOCKETS_MONITOR {
            for key in ["family", "proto", "state"] {
                if json_value::field_u8(data, key).is_none() {
                    return Err(format!("invalid sockets-monitor config: missing {key}"));
                }
            }
            return Ok(());
        }

        return Ok(());
    }

    let Some(pid_raw) = task_runtime_naming::data_or_suffix(
        data,
        "pid",
        task_name,
        task_runtime_naming::TASK_PID_MONITOR,
    ) else {
        return Err("invalid pid for pid-monitor".to_string());
    };

    let Ok(pid) = pid_raw.parse::<u32>() else {
        return Err("invalid pid for pid-monitor".to_string());
    };

    if pid == 0 {
        return Err("invalid pid for pid-monitor".to_string());
    }

    if !proc_pid_exists(pid) {
        return Err("The process is no longer running".to_string());
    }

    Ok(())
}

pub(crate) fn is_runtime_task_name_supported(task_name: &str) -> bool {
    let normalized = task_runtime_naming::normalized_task_name(task_name);
    task_runtime_naming::is_runtime_canonical_task_name(normalized.as_str())
}

pub(crate) fn storage_task_name_supported(task_name: &str) -> bool {
    let normalized = task_runtime_naming::normalized_task_name(task_name);
    task_runtime_naming::is_storage_canonical_task_name(normalized.as_str())
}

use crate::services::task::{TaskRuntimePayload, naming as task_runtime_naming};
use crate::utils::duration_parse::{TASK_INTERVAL_OPTIONS, parse_human_duration};
use crate::utils::proc_fs::proc_pid_exists;

pub(crate) fn validate_task_start_input(
    task_name: &str,
    data: &TaskRuntimePayload,
) -> Result<(), String> {
    let normalized = task_runtime_naming::normalized_task_name(task_name);

    if task_runtime_naming::canonical_task_name_supports_interval(normalized.as_str())
        && let Some(raw_interval) = data.interval_raw()
        && !raw_interval.trim().is_empty()
        && parse_human_duration(raw_interval.trim(), TASK_INTERVAL_OPTIONS).is_none()
    {
        return Err(format!("invalid interval for {normalized}"));
    }

    if normalized != task_runtime_naming::TASK_PID_MONITOR {
        if normalized == task_runtime_naming::TASK_NODE_MONITOR {
            if data.node_name().is_none() {
                return Err("invalid node for node-monitor".to_string());
            }
            return Ok(());
        }

        if normalized == task_runtime_naming::TASK_SOCKETS_MONITOR {
            if data.sockets_family().is_none() {
                return Err("invalid sockets-monitor config: missing family".to_string());
            }
            if data.sockets_proto().is_none() {
                return Err("invalid sockets-monitor config: missing proto".to_string());
            }
            if data.sockets_state().is_none() {
                return Err("invalid sockets-monitor config: missing state".to_string());
            }
            return Ok(());
        }

        return Ok(());
    }

    let Some(pid_raw) = data.pid_raw() else {
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

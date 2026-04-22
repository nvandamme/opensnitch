use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use opensnitch_proto::pb;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::utils::net_iface::{interface_name_by_index, interface_name_map};

use crate::{
    models::{
        proc_net_packet::{ProcNetPacketRow, ProcNetXdpRow},
        task_config::{
            DownloaderTaskConfig, IocReportConfig, IocScannerTaskConfig, IocScheduleConfig,
            IocToolConfig,
        },
        task_storage::{TaskDataFile, TasksListFile},
        ui_alert::UiAlert,
    },
    services::process_service::ProcessService,
};

pub(crate) struct DiskTaskRuntime {
    pub(crate) handle: tokio::task::JoinHandle<()>,
    pub(crate) token: CancellationToken,
    pub(crate) fingerprint: String,
}

#[derive(Debug, Clone)]
pub(crate) enum TaskLifecycleEvent {
    Added { task_name: String, task_key: String },
    Removed { task_name: String, task_key: String },
    PausedAll { task_count: usize },
    ResumedAll { task_count: usize },
}

static ALERT_TX: OnceLock<tokio::sync::mpsc::Sender<UiAlert>> = OnceLock::new();
const DOWNLOADER_SUCCESS_MSG: &str = "[blocklists] lists updated";
const LEGACY_TASK_RESULT_NOTIFY_TYPE: i32 = 9999;

#[derive(Clone, Default)]
pub(crate) struct TaskRuntimeService;

impl TaskRuntimeService {
    fn read_proc_net_packet_rows() -> Vec<ProcNetPacketRow> {
        let Ok(contents) = std::fs::read_to_string("/proc/net/packet") else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for line in contents.lines().skip(1) {
            let mut iface = None;
            let mut uid = None;
            let mut inode = None;

            for (idx, col) in line.split_whitespace().enumerate() {
                match idx {
                    4 => iface = col.parse::<u32>().ok(),
                    7 => uid = col.parse::<u32>().ok(),
                    8 => {
                        inode = col.parse::<u32>().ok();
                        break;
                    }
                    _ => {}
                }
            }

            let (Some(iface), Some(uid), Some(inode)) = (iface, uid, inode) else {
                continue;
            };
            out.push(ProcNetPacketRow { iface, uid, inode });
        }

        out
    }

    fn read_proc_net_xdp_rows() -> Vec<ProcNetXdpRow> {
        let Ok(contents) = std::fs::read_to_string("/proc/net/xdp") else {
            return Vec::new();
        };

        let mut lines = contents.lines();
        let Some(header_line) = lines.next() else {
            return Vec::new();
        };
        let headers: Vec<String> = header_line
            .split_whitespace()
            .map(|h| h.to_ascii_lowercase())
            .collect();

        let idx_of = |names: &[&str]| -> Option<usize> {
            headers.iter().position(|h| names.iter().any(|n| h == n))
        };

        let inode_idx = idx_of(&["inode", "ino"]);
        let uid_idx = idx_of(&["uid"]);
        let iface_idx = idx_of(&["ifindex", "if_idx", "if"]);
        let cookie_idx = idx_of(&["cookie"]);

        let mut out = Vec::new();
        for line in lines {
            let Some(inode_pos) = inode_idx else {
                continue;
            };
            let Some(uid_pos) = uid_idx else {
                continue;
            };
            let Some(if_pos) = iface_idx else {
                continue;
            };

            let mut inode = None;
            let mut uid = None;
            let mut iface = None;
            let mut cookie = None;
            for (idx, col) in line.split_whitespace().enumerate() {
                if idx == inode_pos {
                    inode = col.parse::<u32>().ok();
                } else if idx == uid_pos {
                    uid = col.parse::<u32>().ok();
                } else if idx == if_pos {
                    iface = col.parse::<u32>().ok();
                } else if Some(idx) == cookie_idx {
                    cookie = Some(col);
                }
            }

            let (Some(inode), Some(uid), Some(iface)) = (inode, uid, iface) else {
                continue;
            };

            let (cookie0, cookie1) = if cookie_idx.is_some() {
                let raw = cookie.unwrap_or("0").trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(raw, 16) {
                    ((v & 0xffff_ffff) as u32, ((v >> 32) & 0xffff_ffff) as u32)
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

            out.push(ProcNetXdpRow {
                iface,
                uid,
                inode,
                cookie0,
                cookie1,
            });
        }

        out
    }

    pub(crate) fn configure_alert_sender(&self, alert_tx: tokio::sync::mpsc::Sender<UiAlert>) {
        let _ = ALERT_TX.set(alert_tx);
    }

    pub(crate) async fn sync_disk_tasks(
        &self,
        tasks_file: &std::path::Path,
        task_handles: &mut HashMap<String, DiskTaskRuntime>,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) -> Result<()> {
        let desired = Self::load_disk_tasks(tasks_file).await?;

        task_handles.retain(|key, runtime| {
            if desired.contains_key(key) {
                true
            } else {
                runtime.token.cancel();
                runtime.handle.abort();
                false
            }
        });

        for (key, (task_name, task_data, fingerprint)) in desired {
            if !self.disk_task_name_supported(task_name.as_str()) {
                tracing::debug!(task = %task_name, "skipping unsupported disk task");
                continue;
            }

            if let Some(runtime) = task_handles.get(&key)
                && runtime.fingerprint == fingerprint
            {
                continue;
            }

            if let Some(runtime) = task_handles.remove(&key) {
                tracing::info!(task = %key, "restarting disk task after config change");
                runtime.token.cancel();
                runtime.handle.abort();
            }

            let token = CancellationToken::new();
            let handle = self.spawn_task_monitor_snapshot(
                task_name.as_str(),
                0,
                task_data,
                token.clone(),
                process.clone(),
                task_reply_tx.clone(),
            );
            task_handles.insert(
                key,
                DiskTaskRuntime {
                    handle,
                    token,
                    fingerprint,
                },
            );
        }

        Ok(())
    }

    pub(crate) fn stop_disk_tasks(
        &self,
        task_handles: &mut HashMap<String, DiskTaskRuntime>,
    ) -> usize {
        let stopped = task_handles.len();
        for (_, runtime) in task_handles.drain() {
            runtime.token.cancel();
            runtime.handle.abort();
        }
        stopped
    }

    pub(crate) fn stop_runtime_tasks(
        &self,
        task_handles: &mut HashMap<String, (tokio::task::JoinHandle<()>, CancellationToken)>,
    ) -> usize {
        let stopped = task_handles.len();
        for (_, (handle, token)) in task_handles.drain() {
            token.cancel();
            handle.abort();
        }
        stopped
    }

    pub(crate) fn pause_runtime_tasks(
        &self,
        task_handles: &HashMap<String, (tokio::task::JoinHandle<()>, CancellationToken)>,
    ) -> usize {
        // Forward-compatible Go parity: keep PauseAll surface available even if
        // current runtime monitors do not implement active pausing.
        task_handles.len()
    }

    pub(crate) fn resume_runtime_tasks(
        &self,
        task_handles: &HashMap<String, (tokio::task::JoinHandle<()>, CancellationToken)>,
    ) -> usize {
        // Go parity: task manager exposes ResumeAll(), but concrete runtime monitors
        // implement Resume() as no-op today. Mirror that manager-level surface.
        task_handles.len()
    }

    pub(crate) fn build_task_key(&self, task_name: &str, data: &Value) -> String {
        let normalized_name = self.normalized_task_name(task_name);
        match normalized_name.as_str() {
            "pid-monitor" => format!(
                "pid-monitor:{}",
                Self::data_or_suffix(data, "pid", task_name, "pid-monitor").unwrap_or_default()
            ),
            "node-monitor" => format!(
                "node-monitor:{}",
                Self::data_or_suffix(data, "node", task_name, "node-monitor")
                    .unwrap_or_else(|| "default".to_string())
            ),
            "sockets-monitor" => "sockets-monitor".to_string(),
            _ => normalized_name,
        }
    }

    pub(crate) fn validate_task_start_input(
        &self,
        task_name: &str,
        data: &Value,
    ) -> Result<(), String> {
        let normalized = self.normalized_task_name(task_name);

        if matches!(
            normalized.as_str(),
            "pid-monitor"
                | "node-monitor"
                | "sockets-monitor"
                | "looper"
                | "downloader"
                | "ioc-scanner"
        ) && let Some(raw_interval) = Self::data_string(data, "interval")
            && !raw_interval.trim().is_empty()
            && self.parse_task_interval(raw_interval.trim()).is_none()
        {
            return Err(format!("invalid interval for {normalized}"));
        }

        if normalized != "pid-monitor" {
            if normalized == "node-monitor" {
                if Self::data_or_suffix(data, "node", task_name, "node-monitor").is_none() {
                    return Err("invalid node for node-monitor".to_string());
                }
                return Ok(());
            }

            if normalized == "sockets-monitor" {
                for key in ["family", "proto", "state"] {
                    if Self::data_u8(data, key).is_none() {
                        return Err(format!("invalid sockets-monitor config: missing {key}"));
                    }
                }
                return Ok(());
            }

            return Ok(());
        }

        let Some(pid_raw) = Self::data_or_suffix(data, "pid", task_name, "pid-monitor") else {
            return Err("invalid pid for pid-monitor".to_string());
        };

        let Ok(pid) = pid_raw.parse::<u32>() else {
            return Err("invalid pid for pid-monitor".to_string());
        };

        if pid == 0 {
            return Err("invalid pid for pid-monitor".to_string());
        }

        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return Err("The process is no longer running".to_string());
        }

        Ok(())
    }

    pub(crate) fn is_runtime_task_name_supported(&self, task_name: &str) -> bool {
        matches!(
            self.normalized_task_name(task_name).as_str(),
            "pid-monitor" | "node-monitor" | "sockets-monitor"
        )
    }

    pub(crate) fn normalized_task_name(&self, name: &str) -> String {
        let normalized = name.trim().to_ascii_lowercase();

        if normalized == "pidmonitor"
            || normalized == "pid-monitor"
            || normalized.starts_with("pidmonitor-")
            || normalized.starts_with("pid-monitor-")
        {
            return "pid-monitor".to_string();
        }

        if normalized == "nodemonitor"
            || normalized == "node-monitor"
            || normalized.starts_with("nodemonitor-")
            || normalized.starts_with("node-monitor-")
        {
            return "node-monitor".to_string();
        }

        if normalized == "socketsmonitor"
            || normalized == "sockets-monitor"
            || normalized == "netstat"
            || normalized.starts_with("socketsmonitor-")
            || normalized.starts_with("sockets-monitor-")
            || normalized.starts_with("netstat-")
        {
            return "sockets-monitor".to_string();
        }

        if normalized == "looptask"
            || normalized == "looper"
            || normalized.starts_with("looptask-")
            || normalized.starts_with("looper-")
        {
            return "looper".to_string();
        }

        if normalized == "ioc-scanner"
            || normalized == "iocscanner"
            || normalized.starts_with("ioc-scanner-")
            || normalized.starts_with("iocscanner-")
        {
            return "ioc-scanner".to_string();
        }

        if normalized == "downloader" || normalized.starts_with("downloader-") {
            return "downloader".to_string();
        }

        normalized
    }

    pub(crate) fn disk_task_name_supported(&self, task_name: &str) -> bool {
        matches!(
            self.normalized_task_name(task_name).as_str(),
            "looper" | "downloader" | "ioc-scanner"
        )
    }

    pub(crate) fn matches_ioc_time(&self, spec: &str, hour: u8, minute: u8, second: u8) -> bool {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return false;
        }

        let mut parts = trimmed.split(':');
        let Some(hour_part) = parts.next() else {
            return false;
        };
        let Some(minute_part) = parts.next() else {
            return false;
        };
        let second_part = parts.next();
        if parts.next().is_some() {
            return false;
        }

        let Ok(h) = hour_part.parse::<u8>() else {
            return false;
        };
        let Ok(m) = minute_part.parse::<u8>() else {
            return false;
        };
        let s = if let Some(second_part) = second_part {
            let Ok(s) = second_part.parse::<u8>() else {
                return false;
            };
            s
        } else {
            0
        };

        h == hour && m == minute && s == second
    }

    #[cfg(test)]
    pub(crate) fn ioc_schedule_matches_now(&self, data: &Value, now: time::OffsetDateTime) -> bool {
        let Ok(cfg) = serde_json::from_value::<IocScannerTaskConfig>(data.clone()) else {
            return false;
        };
        Self::ioc_schedule_matches_now_cfg(&cfg, now)
    }

    fn ioc_schedule_matches_now_cfg(cfg: &IocScannerTaskConfig, now: time::OffsetDateTime) -> bool {
        cfg.schedule
            .iter()
            .any(|entry| Self::ioc_schedule_entry_matches_now(entry, now))
    }

    pub(crate) fn parse_task_interval(&self, value: &str) -> Option<std::time::Duration> {
        if let Some(value) = value.strip_suffix("ms")
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_millis(v.max(100)));
        }

        if let Some(value) = value.strip_suffix('s')
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_secs(v.max(1)));
        }

        if let Some(value) = value.strip_suffix('m')
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_secs(v.max(1).saturating_mul(60)));
        }

        if let Some(value) = value.strip_suffix('h')
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_secs(
                v.max(1).saturating_mul(60 * 60),
            ));
        }

        None
    }

    pub(crate) fn build_legacy_downloader_task_result(&self, data: &str) -> Value {
        serde_json::json!({
            "Type": LEGACY_TASK_RESULT_NOTIFY_TYPE,
            "Data": data,
        })
    }

    pub(crate) async fn send_task_reply(
        &self,
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        notification_id: u64,
        code: pb::NotificationReplyCode,
        data: String,
    ) {
        match code {
            pb::NotificationReplyCode::Ok => {
                tracing::info!(notification_id, task_data = %data, "task notification");
            }
            _ => {
                tracing::error!(notification_id, task_data = %data, "task notification error");
            }
        }

        let reply = pb::NotificationReply {
            id: notification_id,
            code: code as i32,
            data,
        };
        match task_reply_tx.try_send(reply) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(reply)) => {
                let _ = task_reply_tx.send(reply).await;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

impl TaskRuntimeService {
    fn task_instance_suffix(task_name: &str, canonical_name: &str) -> Option<String> {
        let raw = task_name.trim();
        let raw_lower = raw.to_ascii_lowercase();
        let prefixes: &[&str] = match canonical_name {
            "pid-monitor" => &["pid-monitor-", "pidmonitor-"],
            "node-monitor" => &["node-monitor-", "nodemonitor-"],
            _ => &[],
        };

        for prefix in prefixes {
            if raw_lower.starts_with(prefix) {
                let suffix = raw.get(prefix.len()..).unwrap_or("").trim();
                if !suffix.is_empty() {
                    return Some(suffix.to_string());
                }
            }
        }

        None
    }

    fn disk_task_fingerprint(path: &std::path::Path, raw_task: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(raw_task.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn data_string(data: &Value, key: &str) -> Option<String> {
        let obj = data.as_object()?;
        obj.get(key).and_then(|v| {
            if let Some(s) = v.as_str() {
                Some(s.to_string())
            } else {
                v.as_u64().map(|n| n.to_string())
            }
        })
    }

    fn data_u8(data: &Value, key: &str) -> Option<u8> {
        let obj = data.as_object()?;
        obj.get(key).and_then(|v| {
            if let Some(n) = v.as_u64() {
                u8::try_from(n).ok()
            } else if let Some(s) = v.as_str() {
                s.parse::<u8>().ok()
            } else {
                None
            }
        })
    }

    fn data_or_suffix(
        data: &Value,
        key: &str,
        task_name: &str,
        canonical_name: &str,
    ) -> Option<String> {
        Self::data_string(data, key)
            .or_else(|| Self::task_instance_suffix(task_name, canonical_name))
    }

    fn task_interval(data: &Value) -> std::time::Duration {
        let raw = Self::data_string(data, "interval").unwrap_or_else(|| "5s".to_string());
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return std::time::Duration::from_secs(5);
        }
        TaskRuntimeService
            .parse_task_interval(trimmed)
            .unwrap_or(std::time::Duration::from_secs(5))
    }

    fn ioc_schedule_entry_matches_now(
        entry: &IocScheduleConfig,
        now: time::OffsetDateTime,
    ) -> bool {
        let weekday = now.weekday().number_days_from_sunday() as u8;
        let weekday_match = entry.weekday.contains(&weekday);
        if !weekday_match {
            return false;
        }

        if entry.time.iter().any(|value| {
            TaskRuntimeService.matches_ioc_time(
                value.as_str(),
                now.hour(),
                now.minute(),
                now.second(),
            )
        }) {
            return true;
        }

        let has_hours = !entry.hour.is_empty();
        let has_minutes = !entry.minute.is_empty();
        let has_seconds = !entry.second.is_empty();
        let hour_matched = has_hours && entry.hour.contains(&(now.hour() as u8));
        let minute_matched = has_minutes && entry.minute.contains(&(now.minute() as u8));
        let second_matched = has_seconds && entry.second.contains(&(now.second() as u8));

        (has_hours && !has_minutes && !has_seconds && hour_matched)
            || (!has_hours && has_minutes && !has_seconds && minute_matched)
            || (!has_hours && !has_minutes && has_seconds && second_matched)
            || (!has_hours && has_minutes && has_seconds && minute_matched && second_matched)
            || (has_hours
                && has_minutes
                && has_seconds
                && hour_matched
                && minute_matched
                && second_matched)
    }

    fn has_ioc_schedule_cfg(cfg: &IocScannerTaskConfig) -> bool {
        cfg.schedule.iter().any(|entry| {
            !entry.time.is_empty()
                || !entry.hour.is_empty()
                || !entry.minute.is_empty()
                || !entry.second.is_empty()
        })
    }

    fn parse_interval_or_default(value: &str, default: std::time::Duration) -> std::time::Duration {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return default;
        }
        TaskRuntimeService
            .parse_task_interval(trimmed)
            .unwrap_or(default)
    }

    fn build_report_path(
        report: &IocReportConfig,
        tool: &IocToolConfig,
    ) -> Result<std::path::PathBuf> {
        let now = time::OffsetDateTime::now_utc();
        let stamp_format =
            time::format_description::parse("[day]-[month]-[year]T[hour]:[minute]:[second]")?;
        let stamp = now.format(&stamp_format)?;
        let tool_name = if tool.name.trim().is_empty() {
            "ioc-tool"
        } else {
            tool.name.trim()
        };

        let extension = if report.format.trim().is_empty() {
            "log"
        } else {
            report.format.trim()
        };

        Ok(std::path::PathBuf::from(report.path.trim())
            .join(format!("ioc-report-{tool_name}-{stamp}.{extension}")))
    }

    fn downloader_go_result_message(payload: &Value) -> String {
        let Some(items) = payload.get("Errors").and_then(Value::as_array) else {
            return DOWNLOADER_SUCCESS_MSG.to_string();
        };

        let mut message = String::from(DOWNLOADER_SUCCESS_MSG);
        let mut has_errors = false;
        for err in items.iter().filter_map(Value::as_str).map(str::trim) {
            if err.is_empty() {
                continue;
            }
            if !has_errors {
                message.push_str("\n\nErrors:\n");
                has_errors = true;
            } else {
                message.push_str(", ");
            }
            message.push_str(err);
        }

        if has_errors {
            message
        } else {
            DOWNLOADER_SUCCESS_MSG.to_string()
        }
    }

    fn emit_legacy_downloader_typed_result(data: &str) {
        // Go parity: downloader emits a second typed TaskResults payload
        // (Type=9999) that the default UI task-event monitor ignores.
        let legacy = TaskRuntimeService.build_legacy_downloader_task_result(data);
        tracing::debug!(target: "opensnitch.task", task = "downloader", legacy_task_result = %legacy, "emitting legacy typed task result");
    }

    async fn load_disk_tasks(
        tasks_file: &std::path::Path,
    ) -> Result<HashMap<String, (String, Arc<Value>, String)>> {
        tracing::debug!(
            "[tasks] Loader.Load() config file: {}",
            tasks_file.display()
        );
        let raw = match tokio::fs::read_to_string(tasks_file).await {
            Ok(raw) => raw,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                tracing::warn!(
                    "[tasks] LoadTaskFile, error loading tasks (), error reading tasks list file {}: {}",
                    tasks_file.display(),
                    err
                );
                return Ok(HashMap::new());
            }
            Err(err) => {
                tracing::warn!(
                    "[tasks] LoadTaskFile, error loading tasks (), error reading tasks list file {}: {}",
                    tasks_file.display(),
                    err
                );
                return Err(err.into());
            }
        };
        let tasks_list = serde_json::from_str::<TasksListFile>(&raw)?;
        let tasks_base_dir = tasks_file
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let mut loaded = HashMap::new();
        for task in tasks_list.tasks.into_iter().filter(|task| task.enabled) {
            if task.config_file.trim().is_empty() {
                continue;
            }

            let config_path = {
                let configured = std::path::PathBuf::from(task.config_file.trim());
                if configured.is_absolute() {
                    configured
                } else {
                    tasks_base_dir.join(configured)
                }
            };

            let raw_task = match tokio::fs::read_to_string(&config_path).await {
                Ok(raw_task) => raw_task,
                Err(_) => continue,
            };
            let parsed = match serde_json::from_str::<TaskDataFile>(&raw_task) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };

            let task_name = if !parsed.parent.trim().is_empty() {
                parsed.parent.trim().to_string()
            } else if !task.name.trim().is_empty() {
                task.name.trim().to_string()
            } else {
                parsed.name.trim().to_string()
            };
            let task_name = TaskRuntimeService.normalized_task_name(&task_name);
            if task_name.is_empty() {
                continue;
            }

            let instance_name = if !parsed.name.trim().is_empty() {
                parsed.name.trim().to_string()
            } else {
                task_name.clone()
            };
            let fingerprint = Self::disk_task_fingerprint(&config_path, &raw_task);

            loaded.insert(
                format!("disk-task:{instance_name}"),
                (task_name, Arc::new(parsed.data), fingerprint),
            );
        }

        Ok(loaded)
    }

    pub(crate) fn spawn_task_monitor_snapshot(
        &self,
        task_name: &str,
        notification_id: u64,
        data: Arc<Value>,
        token: CancellationToken,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
    ) -> tokio::task::JoinHandle<()> {
        tracing::info!("[tasks] Adding task: {task_name}");
        let raw_task_name = task_name.trim().to_string();
        let task_name = TaskRuntimeService.normalized_task_name(task_name);
        match task_name.as_str() {
            "pid-monitor" => {
                let pid = Self::data_or_suffix(data.as_ref(), "pid", &raw_task_name, "pid-monitor")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let interval = Self::task_interval(data.as_ref());
                tokio::spawn(async move {
                    let mut first_run = true;
                    if pid == 0 {
                        Self::send_task_event(
                            &task_reply_tx,
                            "pid-monitor",
                            notification_id,
                            pb::NotificationReplyCode::Error,
                            "invalid pid for pid-monitor".to_string(),
                        )
                        .await;
                        return;
                    }
                    loop {
                        if !first_run {
                            tokio::select! {
                                _ = token.cancelled() => break,
                                _ = tokio::time::sleep(interval) => {}
                            }
                        } else {
                            first_run = false;
                            if token.is_cancelled() {
                                break;
                            }
                        }

                        if token.is_cancelled() {
                            break;
                        }

                        match process.inspect(pid).await {
                            Ok(info) => {
                                let mut checksums = serde_json::Map::new();
                                if let Some(hash) = info.process_hash.as_ref() {
                                    checksums.insert(
                                        "process.hash.sha1".to_string(),
                                        serde_json::Value::String(hash.clone()),
                                    );
                                }

                                let tree = info
                                .parent_chain
                                .iter()
                                .map(|n| serde_json::json!({ "key": n.path.clone(), "value": n.pid }))
                                .collect::<Vec<_>>();

                                let parent_pid =
                                    info.parent_chain.get(1).map(|n| n.pid).unwrap_or(0);

                                if let Ok(raw) = serde_json::to_string(&serde_json::json!({
                                    "Pid": info.pid,
                                    "ID": info.pid,
                                    "Ppid": parent_pid,
                                    "PPID": parent_pid,
                                    "Uid": 0,
                                    "UID": 0,
                                    "Comm": std::path::Path::new(&info.path)
                                        .file_name()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    "Path": info.path,
                                    "Root": "/",
                                    "RealPath": info.path,
                                    "Args": info.args,
                                    "Env": serde_json::Map::<String, serde_json::Value>::new(),
                                    "CWD": info.cwd.unwrap_or_default(),
                                    "Checksums": checksums,
                                    "IOStats": {
                                        "RChar": 0,
                                        "WChar": 0,
                                        "SyscallRead": 0,
                                        "SyscallWrite": 0,
                                        "ReadBytes": 0,
                                        "WriteBytes": 0,
                                    },
                                    "Statm": {
                                        "Size": 0,
                                        "Resident": 0,
                                        "Shared": 0,
                                        "Text": 0,
                                        "Lib": 0,
                                        "Data": 0,
                                        "Dt": 0,
                                    },
                                    "Status": "",
                                    "Stat": "",
                                    "Maps": "",
                                    "Stack": "",
                                    "Descriptors": serde_json::Value::Null,
                                    "NetStats": {
                                        "ReadBytes": 0,
                                        "WriteBytes": 0,
                                    },
                                    "Tree": tree,
                                })) {
                                    tracing::debug!(task = "pid-monitor", pid, data = %raw, "task result");
                                    Self::send_task_event(
                                        &task_reply_tx,
                                        "pid-monitor",
                                        notification_id,
                                        pb::NotificationReplyCode::Ok,
                                        raw,
                                    )
                                    .await;
                                }
                            }
                            Err(err) => {
                                let message = format!("pid-monitor error: {err}");
                                Self::send_task_event(
                                    &task_reply_tx,
                                    "pid-monitor",
                                    notification_id,
                                    pb::NotificationReplyCode::Error,
                                    message.clone(),
                                )
                                .await;
                                tracing::debug!(task = "pid-monitor", pid, "task error: {err}");
                                break;
                            }
                        }
                    }
                })
            }
            "node-monitor" => {
                let node =
                    Self::data_or_suffix(data.as_ref(), "node", &raw_task_name, "node-monitor")
                        .unwrap_or_default();
                let interval = Self::task_interval(data.as_ref());
                tokio::spawn(async move {
                    let mut first_run = true;
                    loop {
                        if !first_run {
                            tokio::select! {
                                _ = token.cancelled() => break,
                                _ = tokio::time::sleep(interval) => {}
                            }
                        } else {
                            first_run = false;
                            if token.is_cancelled() {
                                break;
                            }
                        }

                        if token.is_cancelled() {
                            break;
                        }

                        let info = rustix::system::sysinfo();
                        let payload = serde_json::json!({
                            "Uptime": info.uptime,
                            "Loads": [info.loads[0], info.loads[1], info.loads[2]],
                            "Totalram": info.totalram,
                            "Freeram": info.freeram,
                            "Sharedram": info.sharedram,
                            "Bufferram": info.bufferram,
                            "Totalswap": info.totalswap,
                            "Freeswap": info.freeswap,
                            "Procs": info.procs,
                            "Totalhigh": info.totalhigh,
                            "Freehigh": info.freehigh,
                            "Unit": info.mem_unit,
                        })
                        .to_string();
                        Self::send_task_event(
                            &task_reply_tx,
                            "node-monitor",
                            notification_id,
                            pb::NotificationReplyCode::Ok,
                            payload,
                        )
                        .await;
                        tracing::debug!(task = "node-monitor", node, "task result");
                    }
                })
            }
            "sockets-monitor" => {
                let interval = Self::task_interval(data.as_ref());
                let family =
                    Self::data_u8(data.as_ref(), "family").unwrap_or(nix::libc::AF_INET as u8);
                let proto =
                    Self::data_u8(data.as_ref(), "proto").unwrap_or(nix::libc::IPPROTO_TCP as u8);
                let state_filter = Self::data_u8(data.as_ref(), "state").unwrap_or(0);
                tokio::spawn(async move {
                    let mut first_run = true;
                    loop {
                        if !first_run {
                            tokio::select! {
                                _ = token.cancelled() => break,
                                _ = tokio::time::sleep(interval) => {}
                            }
                        } else {
                            first_run = false;
                            if token.is_cancelled() {
                                break;
                            }
                        }

                        if token.is_cancelled() {
                            break;
                        }

                        let reply = tokio::task::spawn_blocking(move || {
                            crate::adapters::socket_diag::SocketDiagAdapter::dump_sockets(
                                family, proto,
                            )
                        })
                        .await;

                        match reply {
                            Ok(Ok(sockets)) => {
                                let mut inode_pid_cache: HashMap<u32, Option<u32>> = HashMap::new();
                                let mut iface_cache: HashMap<u32, String> = HashMap::new();
                                let rtnl_iface_map = Self::fetch_iface_name_map_rtnetlink().await;
                                let mut process_map =
                                    serde_json::Map::<String, serde_json::Value>::new();
                                let mut table = Vec::with_capacity(sockets.len());

                                for s in &sockets {
                                    if !(state_filter == 0 || state_filter == s.state) {
                                        continue;
                                    }

                                    let pid = if s.inode != 0 {
                                        if let Some(cached) = inode_pid_cache.get(&s.inode) {
                                            *cached
                                        } else {
                                            let resolved =
                                            crate::utils::pid_resolver::PidResolverState::resolve_pid_by_inode_async(
                                                s.inode,
                                            )
                                            .await;
                                            inode_pid_cache.insert(s.inode, resolved);
                                            resolved
                                        }
                                    } else {
                                        None
                                    };

                                    Self::ensure_process_entry(&process, &mut process_map, pid)
                                        .await;

                                    let iface_name = if s.iface == 0 {
                                        String::new()
                                    } else if let Some(name) = iface_cache.get(&s.iface) {
                                        name.clone()
                                    } else {
                                        let name = rtnl_iface_map
                                            .as_ref()
                                            .and_then(|m| m.get(&s.iface).cloned())
                                            .or_else(|| interface_name_by_index(s.iface))
                                            .unwrap_or_default();
                                        iface_cache.insert(s.iface, name.clone());
                                        name
                                    };

                                    table.push(serde_json::json!({
                                        "Socket": {
                                            "ID": {
                                                "Source": s.src.to_string(),
                                                "Destination": s.dst.to_string(),
                                                "Cookie": [s.cookie0, s.cookie1],
                                                "Interface": s.iface,
                                                "SourcePort": s.src_port,
                                                "DestinationPort": s.dst_port,
                                            },
                                            "Expires": s.expires,
                                            "RQueue": s.rqueue,
                                            "WQueue": s.wqueue,
                                            "UID": s.uid,
                                            "INode": s.inode,
                                            "Family": s.family,
                                            "State": s.state,
                                            "Timer": s.timer,
                                            "Retrans": s.retrans,
                                        },
                                        "Iface": iface_name,
                                        "PID": pid.map(|v| v as i32).unwrap_or(-1),
                                        "Mark": s.mark,
                                        "Proto": proto,
                                    }));
                                }

                                if (family == 0 || family == nix::libc::AF_PACKET as u8)
                                    && state_filter == 0
                                {
                                    for pkt in Self::read_proc_net_packet_rows() {
                                        let pid = if pkt.inode != 0 {
                                            if let Some(cached) = inode_pid_cache.get(&pkt.inode) {
                                                *cached
                                            } else {
                                                let resolved = crate::utils::pid_resolver::PidResolverState::resolve_pid_by_inode_async(pkt.inode).await;
                                                inode_pid_cache.insert(pkt.inode, resolved);
                                                resolved
                                            }
                                        } else {
                                            None
                                        };

                                        Self::ensure_process_entry(&process, &mut process_map, pid)
                                            .await;

                                        let iface_name = if pkt.iface == 0 {
                                            String::new()
                                        } else if let Some(name) = iface_cache.get(&pkt.iface) {
                                            name.clone()
                                        } else {
                                            let name = rtnl_iface_map
                                                .as_ref()
                                                .and_then(|m| m.get(&pkt.iface).cloned())
                                                .or_else(|| interface_name_by_index(pkt.iface))
                                                .unwrap_or_default();
                                            iface_cache.insert(pkt.iface, name.clone());
                                            name
                                        };

                                        table.push(serde_json::json!({
                                            "Socket": {
                                                "ID": {
                                                    "Source": "",
                                                    "Destination": "",
                                                    "Cookie": [0, 0],
                                                    "Interface": pkt.iface,
                                                    "SourcePort": 0,
                                                    "DestinationPort": 0,
                                                },
                                                "Expires": 0,
                                                "RQueue": 0,
                                                "WQueue": 0,
                                                "UID": pkt.uid,
                                                "INode": pkt.inode,
                                                "Family": nix::libc::AF_PACKET as u8,
                                                "State": 0,
                                                "Timer": 0,
                                                "Retrans": 0,
                                            },
                                            "Iface": iface_name,
                                            "PID": pid.map(|v| v as i32).unwrap_or(-1),
                                            "Mark": 0,
                                            // Keep Go parity: /proc fallback packet sockets are tagged as raw.
                                            "Proto": nix::libc::IPPROTO_RAW as u16,
                                        }));
                                    }
                                }

                                if (family == 0 || family == AF_XDP_FAMILY) && state_filter == 0 {
                                    for xdp in Self::read_proc_net_xdp_rows() {
                                        let pid = if xdp.inode != 0 {
                                            if let Some(cached) = inode_pid_cache.get(&xdp.inode) {
                                                *cached
                                            } else {
                                                let resolved = crate::utils::pid_resolver::PidResolverState::resolve_pid_by_inode_async(xdp.inode).await;
                                                inode_pid_cache.insert(xdp.inode, resolved);
                                                resolved
                                            }
                                        } else {
                                            None
                                        };

                                        Self::ensure_process_entry(&process, &mut process_map, pid)
                                            .await;

                                        let iface_name = if xdp.iface == 0 {
                                            String::new()
                                        } else if let Some(name) = iface_cache.get(&xdp.iface) {
                                            name.clone()
                                        } else {
                                            let name = rtnl_iface_map
                                                .as_ref()
                                                .and_then(|m| m.get(&xdp.iface).cloned())
                                                .or_else(|| interface_name_by_index(xdp.iface))
                                                .unwrap_or_default();
                                            iface_cache.insert(xdp.iface, name.clone());
                                            name
                                        };

                                        table.push(serde_json::json!({
                                            "Socket": {
                                                "ID": {
                                                    "Source": "",
                                                    "Destination": "",
                                                    "Cookie": [xdp.cookie0, xdp.cookie1],
                                                    "Interface": xdp.iface,
                                                    "SourcePort": 0,
                                                    "DestinationPort": 0,
                                                },
                                                "Expires": 0,
                                                "RQueue": 0,
                                                "WQueue": 0,
                                                "UID": xdp.uid,
                                                "INode": xdp.inode,
                                                "Family": AF_XDP_FAMILY,
                                                "State": 0,
                                                "Timer": 0,
                                                "Retrans": 0,
                                            },
                                            "Iface": iface_name,
                                            "PID": pid.map(|v| v as i32).unwrap_or(-1),
                                            "Mark": 0,
                                            "Proto": nix::libc::IPPROTO_RAW,
                                        }));
                                    }
                                }

                                let payload = serde_json::json!({
                                    "Table": table,
                                    "Processes": process_map,
                                })
                                .to_string();
                                Self::send_task_event(
                                    &task_reply_tx,
                                    "sockets-monitor",
                                    notification_id,
                                    pb::NotificationReplyCode::Ok,
                                    payload,
                                )
                                .await;
                                tracing::debug!(
                                    task = "sockets-monitor",
                                    family,
                                    proto,
                                    count = sockets.len(),
                                    "task result"
                                );
                            }
                            Ok(Err(err)) => {
                                let message = format!("sockets-monitor error: {err}");
                                Self::send_task_event(
                                    &task_reply_tx,
                                    "sockets-monitor",
                                    notification_id,
                                    pb::NotificationReplyCode::Error,
                                    message.clone(),
                                )
                                .await;
                                tracing::debug!(
                                    task = "sockets-monitor",
                                    family,
                                    proto,
                                    "task error: {err}"
                                );
                            }
                            Err(err) => {
                                let message = format!("sockets-monitor join error: {err}");
                                Self::send_task_event(
                                    &task_reply_tx,
                                    "sockets-monitor",
                                    notification_id,
                                    pb::NotificationReplyCode::Error,
                                    message.clone(),
                                )
                                .await;
                                tracing::debug!(
                                    task = "sockets-monitor",
                                    family,
                                    proto,
                                    "task error: {err}"
                                );
                            }
                        }
                    }
                })
            }
            "looper" => {
                let interval_raw = Self::data_string(data.as_ref(), "interval")
                    .filter(|raw| !raw.trim().is_empty())
                    .unwrap_or_else(|| "5s".to_string());
                let interval = Self::parse_interval_or_default(
                    interval_raw.as_str(),
                    std::time::Duration::from_secs(5),
                );
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = tokio::time::sleep(interval) => {
                                Self::send_task_event(
                                    &task_reply_tx,
                                    "looper",
                                    notification_id,
                                    pb::NotificationReplyCode::Ok,
                                    interval_raw.clone(),
                                )
                                .await;
                            }
                        }
                    }
                })
            }
            "downloader" => {
                let interval = Self::task_interval(data.as_ref());
                let downloader_cfg =
                    serde_json::from_value::<DownloaderTaskConfig>(data.as_ref().clone())
                        .ok()
                        .map(Arc::new);
                let notify_enabled = downloader_cfg
                    .as_ref()
                    .map(|cfg| cfg.notify.enabled)
                    .unwrap_or(false);
                tokio::spawn(async move {
                    loop {
                        let run_result = if let Some(cfg) = downloader_cfg.as_ref() {
                            Self::run_downloader_once_cfg(cfg.as_ref()).await
                        } else {
                            Err(anyhow::anyhow!("invalid downloader config"))
                        };

                        if notify_enabled {
                            let (code, payload) = match run_result {
                                Ok(payload) => (
                                    pb::NotificationReplyCode::Ok,
                                    Self::downloader_go_result_message(&payload),
                                ),
                                Err(err) => (
                                    pb::NotificationReplyCode::Error,
                                    serde_json::json!({
                                        "Task": "downloader",
                                        "Error": err.to_string(),
                                    })
                                    .to_string(),
                                ),
                            };
                            let legacy_payload = payload.clone();
                            Self::send_task_event(
                                &task_reply_tx,
                                "downloader",
                                notification_id,
                                code,
                                payload,
                            )
                            .await;
                            Self::emit_legacy_downloader_typed_result(&legacy_payload);
                        } else if let Err(err) = run_result {
                            tracing::debug!("downloader run completed with non-fatal error: {err}");
                        }

                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = tokio::time::sleep(interval) => {}
                        }
                    }
                })
            }
            "ioc-scanner" => {
                let interval = Self::task_interval(data.as_ref());
                let ioc_cfg = serde_json::from_value::<IocScannerTaskConfig>(data.as_ref().clone())
                    .ok()
                    .map(Arc::new);
                let use_schedule = ioc_cfg
                    .as_ref()
                    .map(|cfg| Self::has_ioc_schedule_cfg(cfg.as_ref()))
                    .unwrap_or(false);
                tokio::spawn(async move {
                    let mut last_schedule_second = -1_i64;
                    loop {
                        if use_schedule {
                            let now = time::OffsetDateTime::now_utc();
                            let now_second = now.unix_timestamp();
                            if ioc_cfg
                                .as_ref()
                                .map(|cfg| {
                                    TaskRuntimeService::ioc_schedule_matches_now_cfg(
                                        cfg.as_ref(),
                                        now,
                                    )
                                })
                                .unwrap_or(false)
                                && now_second != last_schedule_second
                            {
                                let run_result = if let Some(cfg) = ioc_cfg.as_ref() {
                                    Self::run_ioc_scanner_once_cfg(cfg.as_ref()).await
                                } else {
                                    Err(anyhow::anyhow!("invalid ioc-scanner config"))
                                };

                                match run_result {
                                    Ok(payloads) => {
                                        for payload in payloads {
                                            Self::send_task_event(
                                                &task_reply_tx,
                                                "ioc-scanner",
                                                notification_id,
                                                pb::NotificationReplyCode::Ok,
                                                payload,
                                            )
                                            .await;
                                        }
                                    }
                                    Err(err) => {
                                        let payload = serde_json::json!({
                                            "Task": "ioc-scanner",
                                            "Error": err.to_string(),
                                        })
                                        .to_string();
                                        Self::send_task_event(
                                            &task_reply_tx,
                                            "ioc-scanner",
                                            notification_id,
                                            pb::NotificationReplyCode::Error,
                                            payload,
                                        )
                                        .await;
                                    }
                                }
                                last_schedule_second = now_second;
                            }

                            tokio::select! {
                                _ = token.cancelled() => break,
                                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                            }
                            continue;
                        }
                        // Go parity: IOC scanner schedules executions only through scheduler entries.
                        // When no schedule is configured, keep task alive but emit no periodic results.
                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = tokio::time::sleep(interval) => {}
                        }
                    }
                })
            }
            _ => {
                let task_name = task_name.to_string();
                tokio::spawn(async move {
                    Self::send_task_event(
                        &task_reply_tx,
                        task_name.as_str(),
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        format!("unsupported task: {task_name}"),
                    )
                    .await;
                    let _ = token.cancelled().await;
                })
            }
        }
    }
    async fn send_task_event(
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        task_name: &str,
        notification_id: u64,
        code: pb::NotificationReplyCode,
        data: String,
    ) {
        let is_stream_notification = notification_id > 10_000;

        if is_stream_notification {
            TaskRuntimeService
                .send_task_reply(task_reply_tx, notification_id, code, data)
                .await;
            return;
        }

        let task_notification = serde_json::json!({
            "Name": task_name,
            "Data": data,
        });
        crate::logging::LoggingState::forward_task_notification(
            task_name,
            task_notification
                .get("Data")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
            code != pb::NotificationReplyCode::Ok,
        );

        let payload = task_notification
            .get("Data")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();

        if let Some(alert_tx) = ALERT_TX.get() {
            if code == pb::NotificationReplyCode::Ok {
                crate::models::ui_alert::enqueue_alert(alert_tx, UiAlert::info(payload));
            } else {
                crate::models::ui_alert::enqueue_alert(alert_tx, UiAlert::error(payload));
            }
        }
    }

    async fn run_downloader_once_cfg(cfg: &DownloaderTaskConfig) -> Result<Value> {
        let timeout =
            Self::parse_interval_or_default(&cfg.timeout, std::time::Duration::from_secs(5));
        let client = reqwest::Client::builder().timeout(timeout).build()?;

        let mut sources = 0usize;
        let mut updated = 0usize;
        let mut failed = 0usize;
        let mut errors = Vec::new();

        for source in cfg.urls.iter().filter(|source| source.enabled) {
            if source.remote.trim().is_empty() || source.local_file.trim().is_empty() {
                continue;
            }

            sources = sources.saturating_add(1);

            let local_path = std::path::PathBuf::from(source.local_file.trim());
            if let Some(parent) = local_path.parent()
                && let Err(err) = tokio::fs::create_dir_all(parent).await
            {
                failed = failed.saturating_add(1);
                errors.push(format!(
                    "{}: cannot create destination directory: {err}",
                    source.name
                ));
                continue;
            }

            let download_result = async {
                let response = client.get(source.remote.trim()).send().await?;
                if !response.status().is_success() {
                    anyhow::bail!("http status {}", response.status().as_u16());
                }

                let body = response.bytes().await?;
                if body.is_empty() {
                    anyhow::bail!("empty response body");
                }

                tokio::fs::write(&local_path, body).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(err) = download_result {
                failed = failed.saturating_add(1);
                let label = if source.name.trim().is_empty() {
                    source.remote.trim().to_string()
                } else {
                    source.name.trim().to_string()
                };
                errors.push(format!("{label}: {err}"));
            } else {
                updated = updated.saturating_add(1);
            }
        }

        let status = if failed == 0 { "updated" } else { "partial" };
        Ok(serde_json::json!({
            "Task": "downloader",
            "Status": status,
            "Sources": sources,
            "Updated": updated,
            "Failed": failed,
            "Errors": errors,
        }))
    }

    async fn run_ioc_scanner_once_cfg(cfg: &IocScannerTaskConfig) -> Result<Vec<String>> {
        let global_timeout =
            Self::parse_interval_or_default(&cfg.timeout, std::time::Duration::from_secs(30));
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown-host".to_string());

        let mut reports = Vec::new();
        let mut tools_ran = 0usize;

        for tool in cfg.tools.iter().filter(|tool| tool.enabled) {
            if tool.cmd.is_empty() || tool.cmd[0].trim().is_empty() {
                continue;
            }

            tools_ran = tools_ran.saturating_add(1);

            let timeout =
                Self::parse_interval_or_default(&tool.options.max_running_time, global_timeout);
            let started_at = std::time::Instant::now();
            let command = tool.cmd[0].as_str();
            let args = &tool.cmd[1..];

            let output_result = tokio::time::timeout(timeout, async {
                tokio::process::Command::new(command)
                    .args(args)
                    .output()
                    .await
            })
            .await;

            match output_result {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let merged = format!("{stdout}{stderr}");
                    let html_report = merged.replace('\n', "<br>");

                    if let Err(err) = Self::write_ioc_report_files(&tool, &html_report).await {
                        tracing::debug!(tool = %tool.name, "failed to write IOC report files: {err}");
                    }

                    let started_human = time::OffsetDateTime::now_utc();
                    let stamp_format = time::format_description::parse(
                        "[day]-[month]-[year], [hour]:[minute]:[second]",
                    )?;
                    let started_stamp = started_human.format(&stamp_format)?;
                    let duration = started_at.elapsed().as_secs();

                    reports.push(
                        format!(
                            "==== {} - {} ({}) ====\n\n{}\n\n=== {} - ({}s) ===",
                            tool.name, hostname, started_stamp, merged, tool.name, duration
                        )
                        .replace('\n', "<br>"),
                    );
                }
                Ok(Err(err)) => {
                    reports.push(format!("{}: failed to execute command: {err}", tool.name));
                }
                Err(_) => {
                    reports.push(format!(
                        "{}: timed out after {}ms",
                        tool.name,
                        timeout.as_millis()
                    ));
                }
            }
        }

        if tools_ran == 0 {
            anyhow::bail!("no tools configured");
        }

        Ok(reports)
    }

    async fn write_ioc_report_files(tool: &IocToolConfig, report: &str) -> Result<()> {
        for report_cfg in tool.options.reports.iter().filter(|cfg| {
            cfg.r#type.trim().eq_ignore_ascii_case("file") && !cfg.path.trim().is_empty()
        }) {
            let report_path = Self::build_report_path(report_cfg, tool)?;
            if let Some(parent) = report_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(report_path, report).await?;
        }

        Ok(())
    }

    async fn ensure_process_entry(
        process: &ProcessService,
        process_map: &mut serde_json::Map<String, serde_json::Value>,
        pid: Option<u32>,
    ) {
        let key = pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-1".to_string());

        if process_map.contains_key(&key) {
            return;
        }

        if let Some(pid) = pid {
            if let Ok(info) = process.inspect(pid).await {
                let process_path = info.path.clone();
                let comm = std::path::Path::new(&process_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
                    .to_string();
                process_map.insert(
                    key,
                    serde_json::json!({
                        "Pid": pid,
                        "Path": process_path,
                        "Comm": comm,
                        "Args": info.args,
                        "CWD": info.cwd.unwrap_or_default(),
                    }),
                );
                return;
            }

            process_map.insert(
                key,
                serde_json::json!({
                    "Pid": pid,
                    "Path": "",
                    "Comm": "",
                    "Args": [],
                    "CWD": "",
                }),
            );
            return;
        }

        process_map.insert(
            key,
            serde_json::json!({
                "Pid": -1,
                "Path": "",
                "Comm": "",
                "Args": [],
                "CWD": "",
            }),
        );
    }

    async fn fetch_iface_name_map_rtnetlink() -> Option<HashMap<u32, String>> {
        let map = interface_name_map();
        if map.is_empty() { None } else { Some(map) }
    }
}

const AF_XDP_FAMILY: u8 = 44;

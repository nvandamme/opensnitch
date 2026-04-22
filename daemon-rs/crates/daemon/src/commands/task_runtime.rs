use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use opensnitch_proto::pb;
use rtnetlink::packet_route::link::LinkAttribute;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::{
    models::{
        proc_net_packet::{ProcNetPacketRow, ProcNetXdpRow},
        task_config::{
            DownloaderTaskConfig, IocReportConfig, IocScannerTaskConfig, IocScheduleConfig,
            IocToolConfig,
        },
        task_storage::{TaskDataFile, TasksListFile},
    },
    services::process_service::ProcessService,
};

pub(crate) struct DiskTaskRuntime {
    handle: tokio::task::JoinHandle<()>,
    token: CancellationToken,
    fingerprint: String,
}

const DISK_TASK_REPLY_ID_BASE: u64 = 10_001;
static DISK_TASK_REPLY_ID_COUNTER: AtomicU64 = AtomicU64::new(DISK_TASK_REPLY_ID_BASE);

fn next_disk_task_reply_id() -> u64 {
    DISK_TASK_REPLY_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

trait TaskNameExt {
    fn normalized_task_name(&self) -> String;
    fn is_runtime_task_name_supported(&self) -> bool;
    fn is_disk_task_name_supported(&self) -> bool;
    fn task_instance_suffix(&self, canonical_name: &str) -> Option<String>;
}

impl TaskNameExt for str {
    fn normalized_task_name(&self) -> String {
        let normalized = self.trim().to_ascii_lowercase();

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
            || normalized.starts_with("socketsmonitor-")
            || normalized.starts_with("sockets-monitor-")
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

    fn is_runtime_task_name_supported(&self) -> bool {
        matches!(
            self.normalized_task_name().as_str(),
            "pid-monitor" | "node-monitor" | "sockets-monitor"
        )
    }

    fn is_disk_task_name_supported(&self) -> bool {
        matches!(
            self.normalized_task_name().as_str(),
            "looper" | "downloader" | "ioc-scanner"
        )
    }

    fn task_instance_suffix(&self, canonical_name: &str) -> Option<String> {
        let raw = self.trim();
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
}

trait DiskTaskFingerprintExt {
    fn disk_task_fingerprint(&self, raw_task: &str) -> String;
}

impl DiskTaskFingerprintExt for std::path::Path {
    fn disk_task_fingerprint(&self, raw_task: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(raw_task.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

trait TaskDataExt {
    fn data_string(&self, key: &str) -> Option<String>;
    fn data_u8(&self, key: &str) -> Option<u8>;
    fn data_or_suffix(&self, key: &str, task_name: &str, canonical_name: &str) -> Option<String>;
    fn task_interval(&self) -> std::time::Duration;
}

impl TaskDataExt for Value {
    fn data_string(&self, key: &str) -> Option<String> {
        let obj = self.as_object()?;
        obj.get(key).and_then(|v| {
            if let Some(s) = v.as_str() {
                Some(s.to_string())
            } else {
                v.as_u64().map(|n| n.to_string())
            }
        })
    }

    fn data_u8(&self, key: &str) -> Option<u8> {
        let obj = self.as_object()?;
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

    fn data_or_suffix(&self, key: &str, task_name: &str, canonical_name: &str) -> Option<String> {
        self.data_string(key)
            .or_else(|| task_name.task_instance_suffix(canonical_name))
    }

    fn task_interval(&self) -> std::time::Duration {
        let raw = self
            .data_string("interval")
            .unwrap_or_else(|| "5s".to_string());
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return std::time::Duration::from_secs(5);
        }
        trimmed
            .parse_task_interval()
            .unwrap_or(std::time::Duration::from_secs(5))
    }
}

trait IocTimeSpecExt {
    fn matches_ioc_time(&self, hour: u8, minute: u8, second: u8) -> bool;
}

impl IocTimeSpecExt for str {
    fn matches_ioc_time(&self, hour: u8, minute: u8, second: u8) -> bool {
        let trimmed = self.trim();
        if trimmed.is_empty() {
            return false;
        }

        let parts = trimmed.split(':').collect::<Vec<_>>();
        if parts.len() != 2 && parts.len() != 3 {
            return false;
        }

        let Ok(h) = parts[0].parse::<u8>() else {
            return false;
        };
        let Ok(m) = parts[1].parse::<u8>() else {
            return false;
        };
        let s = if parts.len() == 3 {
            let Ok(s) = parts[2].parse::<u8>() else {
                return false;
            };
            s
        } else {
            0
        };

        h == hour && m == minute && s == second
    }
}

trait IocScheduleEntryExt {
    fn matches_now(&self, now: time::OffsetDateTime) -> bool;
}

impl IocScheduleEntryExt for IocScheduleConfig {
    fn matches_now(&self, now: time::OffsetDateTime) -> bool {
        let weekday = now.weekday().number_days_from_sunday() as u8;
        let weekday_match = self.weekday.iter().any(|value| *value == weekday);
        if !weekday_match {
            return false;
        }

        if self.time.iter().any(|value| {
            value
                .as_str()
                .matches_ioc_time(now.hour(), now.minute(), now.second())
        }) {
            return true;
        }

        let has_hours = !self.hour.is_empty();
        let has_minutes = !self.minute.is_empty();
        let has_seconds = !self.second.is_empty();
        let hour_matched = has_hours && self.hour.iter().any(|value| *value == now.hour() as u8);
        let minute_matched =
            has_minutes && self.minute.iter().any(|value| *value == now.minute() as u8);
        let second_matched =
            has_seconds && self.second.iter().any(|value| *value == now.second() as u8);

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
}

trait IocTaskDataExt {
    fn has_ioc_schedule(&self) -> bool;
    fn ioc_schedule_matches_now(&self, now: time::OffsetDateTime) -> bool;
}

impl IocTaskDataExt for Value {
    fn has_ioc_schedule(&self) -> bool {
        serde_json::from_value::<IocScannerTaskConfig>(self.clone())
            .map(|cfg| {
                cfg.schedule.iter().any(|entry| {
                    !entry.time.is_empty()
                        || !entry.hour.is_empty()
                        || !entry.minute.is_empty()
                        || !entry.second.is_empty()
                })
            })
            .unwrap_or(false)
    }

    fn ioc_schedule_matches_now(&self, now: time::OffsetDateTime) -> bool {
        let Ok(cfg) = serde_json::from_value::<IocScannerTaskConfig>(self.clone()) else {
            return false;
        };

        cfg.schedule.iter().any(|entry| entry.matches_now(now))
    }
}

trait TaskIntervalSpecExt {
    fn parse_task_interval(&self) -> Option<std::time::Duration>;
    fn parse_or_default(&self, default: std::time::Duration) -> std::time::Duration;
}

impl TaskIntervalSpecExt for str {
    fn parse_task_interval(&self) -> Option<std::time::Duration> {
        if let Some(value) = self.strip_suffix("ms")
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_millis(v.max(100)));
        }

        if let Some(value) = self.strip_suffix('s')
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_secs(v.max(1)));
        }

        if let Some(value) = self.strip_suffix('m')
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_secs(v.max(1).saturating_mul(60)));
        }

        if let Some(value) = self.strip_suffix('h')
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(std::time::Duration::from_secs(
                v.max(1).saturating_mul(60 * 60),
            ));
        }

        None
    }

    fn parse_or_default(&self, default: std::time::Duration) -> std::time::Duration {
        let trimmed = self.trim();
        if trimmed.is_empty() {
            return default;
        }
        trimmed.parse_task_interval().unwrap_or(default)
    }
}

trait IocReportPathExt {
    fn build_report_path(&self, tool: &IocToolConfig) -> Result<std::path::PathBuf>;
}

impl IocReportPathExt for IocReportConfig {
    fn build_report_path(&self, tool: &IocToolConfig) -> Result<std::path::PathBuf> {
        let now = time::OffsetDateTime::now_utc();
        let stamp_format =
            time::format_description::parse("[day]-[month]-[year]T[hour]:[minute]:[second]")?;
        let stamp = now.format(&stamp_format)?;
        let tool_name = if tool.name.trim().is_empty() {
            "ioc-tool"
        } else {
            tool.name.trim()
        };

        let extension = if self.format.trim().is_empty() {
            "log"
        } else {
            self.format.trim()
        };

        Ok(std::path::PathBuf::from(self.path.trim())
            .join(format!("ioc-report-{tool_name}-{stamp}.{extension}")))
    }
}

pub(crate) async fn sync_disk_tasks(
    tasks_file: &std::path::Path,
    task_handles: &mut HashMap<String, DiskTaskRuntime>,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
) -> Result<()> {
    let desired = load_disk_tasks(tasks_file).await?;

    let stale_keys = task_handles
        .keys()
        .filter(|key| !desired.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();

    for key in stale_keys {
        if let Some(runtime) = task_handles.remove(&key) {
            runtime.token.cancel();
            runtime.handle.abort();
        }
    }

    for (key, (task_name, task_data, fingerprint)) in desired {
        if !task_name.as_str().is_disk_task_name_supported() {
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
        let handle = spawn_task_monitor(
            task_name.as_str(),
            0,
            &task_data,
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

pub(crate) fn stop_disk_tasks(task_handles: &mut HashMap<String, DiskTaskRuntime>) -> usize {
    let stopped = task_handles.len();
    for (_, runtime) in task_handles.drain() {
        runtime.token.cancel();
        runtime.handle.abort();
    }
    stopped
}

pub(crate) fn stop_runtime_tasks(
    task_handles: &mut HashMap<String, (tokio::task::JoinHandle<()>, CancellationToken)>,
) -> usize {
    let stopped = task_handles.len();
    for (_, (handle, token)) in task_handles.drain() {
        token.cancel();
        handle.abort();
    }
    stopped
}

async fn load_disk_tasks(
    tasks_file: &std::path::Path,
) -> Result<HashMap<String, (String, Value, String)>> {
    let raw = match tokio::fs::read_to_string(tasks_file).await {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => return Err(err.into()),
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
        let task_name = task_name.normalized_task_name();
        if task_name.is_empty() {
            continue;
        }

        let instance_name = if !parsed.name.trim().is_empty() {
            parsed.name.trim().to_string()
        } else {
            task_name.clone()
        };
        let fingerprint = config_path.disk_task_fingerprint(&raw_task);

        loaded.insert(
            format!("disk-task:{instance_name}"),
            (task_name, parsed.data, fingerprint),
        );
    }

    Ok(loaded)
}

pub(crate) fn build_task_key(task_name: &str, data: &Value) -> String {
    let normalized_name = task_name.normalized_task_name();
    match normalized_name.as_str() {
        "pid-monitor" => format!(
            "pid-monitor:{}",
            data.data_or_suffix("pid", task_name, "pid-monitor")
                .unwrap_or_default()
        ),
        "node-monitor" => format!(
            "node-monitor:{}",
            data.data_or_suffix("node", task_name, "node-monitor")
                .unwrap_or_else(|| "default".to_string())
        ),
        "sockets-monitor" => "sockets-monitor".to_string(),
        _ => normalized_name,
    }
}

pub(crate) fn spawn_task_monitor(
    task_name: &str,
    notification_id: u64,
    data: &Value,
    token: CancellationToken,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
) -> tokio::task::JoinHandle<()> {
    let raw_task_name = task_name.trim().to_string();
    let task_name = task_name.normalized_task_name();
    match task_name.as_str() {
        "pid-monitor" => {
            let pid = data
                .data_or_suffix("pid", &raw_task_name, "pid-monitor")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            let interval = data.task_interval();
            tokio::spawn(async move {
                if pid == 0 {
                    send_task_reply(
                        &task_reply_tx,
                        notification_id,
                        pb::NotificationReplyCode::Error,
                        "invalid pid for pid-monitor".to_string(),
                    )
                    .await;
                    return;
                }
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
                            match process.inspect(pid).await {
                                Ok(info) => {
                                    let mut checksums = serde_json::Map::new();
                                    if let Some(hash) = info.process_hash.clone() {
                                        checksums.insert(
                                            "process.hash.sha1".to_string(),
                                            serde_json::Value::String(hash),
                                        );
                                    }

                                    let tree = info
                                        .parent_chain
                                        .iter()
                                        .map(|n| serde_json::json!({ "key": n.path.clone(), "value": n.pid }))
                                        .collect::<Vec<_>>();

                                    if let Ok(raw) = serde_json::to_string(&serde_json::json!({
                                        "Pid": info.pid,
                                        "ID": info.pid,
                                        "Ppid": info.parent_chain.get(1).map(|n| n.pid).unwrap_or(0),
                                        "PPID": info.parent_chain.get(1).map(|n| n.pid).unwrap_or(0),
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
                                        send_task_reply(
                                            &task_reply_tx,
                                            notification_id,
                                            pb::NotificationReplyCode::Ok,
                                            raw.clone(),
                                        )
                                        .await;
                                        tracing::debug!(task = "pid-monitor", pid, data = %raw, "task result");
                                    }
                                }
                                Err(err) => {
                                    let message = format!("pid-monitor error: {err}");
                                    send_task_reply(
                                        &task_reply_tx,
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
                    }
                }
            })
        }
        "node-monitor" => {
            let node = data
                .data_or_suffix("node", &raw_task_name, "node-monitor")
                .unwrap_or_default();
            let interval = data.task_interval();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
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
                            send_task_reply(
                                &task_reply_tx,
                                notification_id,
                                pb::NotificationReplyCode::Ok,
                                payload,
                            )
                            .await;
                            tracing::debug!(task = "node-monitor", node, "task result");
                        }
                    }
                }
            })
        }
        "sockets-monitor" => {
            let interval = data.task_interval();
            let family = data.data_u8("family").unwrap_or(nix::libc::AF_INET as u8);
            let proto = data
                .data_u8("proto")
                .unwrap_or(nix::libc::IPPROTO_TCP as u8);
            let state_filter = data.data_u8("state").unwrap_or(0);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
                            let reply = tokio::task::spawn_blocking(move || {
                                crate::adapters::socket_diag::dump_sockets(family, proto)
                            })
                            .await;

                            match reply {
                                Ok(Ok(sockets)) => {
                                    let mut inode_pid_cache: HashMap<u32, Option<u32>> = HashMap::new();
                                    let mut iface_cache: HashMap<u32, String> = HashMap::new();
                                    let rtnl_iface_map = fetch_iface_name_map_rtnetlink().await;
                                    let mut process_map = serde_json::Map::<String, serde_json::Value>::new();
                                    let mut table = Vec::with_capacity(sockets.len());

                                    for s in &sockets {
                                        if !(state_filter == 0 || state_filter == s.state) {
                                            continue;
                                        }

                                        let pid = if s.inode != 0 {
                                            if let Some(cached) = inode_pid_cache.get(&s.inode) {
                                                *cached
                                            } else {
                                                    let resolved = crate::utils::pid_resolver::resolve_pid_by_inode_async(s.inode).await;
                                                inode_pid_cache.insert(s.inode, resolved);
                                                resolved
                                            }
                                        } else {
                                            None
                                        };

                                        ensure_process_entry(&process, &mut process_map, pid).await;

                                        let iface_name = if s.iface == 0 {
                                            String::new()
                                        } else if let Some(name) = iface_cache.get(&s.iface) {
                                            name.clone()
                                        } else {
                                            let name = rtnl_iface_map
                                                .as_ref()
                                                .and_then(|m| m.get(&s.iface).cloned())
                                                .or_else(|| resolve_iface_name_sysfs(s.iface))
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

                                    if (family == 0 || family == nix::libc::AF_PACKET as u8) && state_filter == 0 {
                                        for pkt in read_proc_net_packet_rows() {
                                            let pid = if pkt.inode != 0 {
                                                if let Some(cached) = inode_pid_cache.get(&pkt.inode) {
                                                    *cached
                                                } else {
                                                    let resolved = crate::utils::pid_resolver::resolve_pid_by_inode_async(pkt.inode).await;
                                                    inode_pid_cache.insert(pkt.inode, resolved);
                                                    resolved
                                                }
                                            } else {
                                                None
                                            };

                                            ensure_process_entry(&process, &mut process_map, pid).await;

                                            let iface_name = if pkt.iface == 0 {
                                                String::new()
                                            } else if let Some(name) = iface_cache.get(&pkt.iface) {
                                                name.clone()
                                            } else {
                                                let name = rtnl_iface_map
                                                    .as_ref()
                                                    .and_then(|m| m.get(&pkt.iface).cloned())
                                                    .or_else(|| resolve_iface_name_sysfs(pkt.iface))
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
                                                "Proto": pkt.proto,
                                            }));
                                        }
                                    }

                                    if (family == 0 || family == AF_XDP_FAMILY) && state_filter == 0 {
                                        for xdp in read_proc_net_xdp_rows() {
                                            let pid = if xdp.inode != 0 {
                                                if let Some(cached) = inode_pid_cache.get(&xdp.inode) {
                                                    *cached
                                                } else {
                                                    let resolved = crate::utils::pid_resolver::resolve_pid_by_inode_async(xdp.inode).await;
                                                    inode_pid_cache.insert(xdp.inode, resolved);
                                                    resolved
                                                }
                                            } else {
                                                None
                                            };

                                            ensure_process_entry(&process, &mut process_map, pid).await;

                                            let iface_name = if xdp.iface == 0 {
                                                String::new()
                                            } else if let Some(name) = iface_cache.get(&xdp.iface) {
                                                name.clone()
                                            } else {
                                                let name = rtnl_iface_map
                                                    .as_ref()
                                                    .and_then(|m| m.get(&xdp.iface).cloned())
                                                    .or_else(|| resolve_iface_name_sysfs(xdp.iface))
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
                                    send_task_reply(
                                        &task_reply_tx,
                                        notification_id,
                                        pb::NotificationReplyCode::Ok,
                                        payload,
                                    )
                                    .await;
                                    tracing::debug!(task = "sockets-monitor", family, proto, count = sockets.len(), "task result");
                                }
                                Ok(Err(err)) => {
                                    let message = format!("sockets-monitor error: {err}");
                                    send_task_reply(
                                        &task_reply_tx,
                                        notification_id,
                                        pb::NotificationReplyCode::Error,
                                        message.clone(),
                                    )
                                    .await;
                                    tracing::debug!(task = "sockets-monitor", family, proto, "task error: {err}");
                                }
                                Err(err) => {
                                    let message = format!("sockets-monitor join error: {err}");
                                    send_task_reply(
                                        &task_reply_tx,
                                        notification_id,
                                        pb::NotificationReplyCode::Error,
                                        message.clone(),
                                    )
                                    .await;
                                    tracing::debug!(task = "sockets-monitor", family, proto, "task error: {err}");
                                }
                            }
                        }
                    }
                }
            })
        }
        "looper" => {
            let interval = data.task_interval();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
                            let payload = serde_json::json!({
                                "Task": "looper",
                                "Interval": format!("{}ms", interval.as_millis()),
                            })
                            .to_string();
                            send_task_reply(
                                &task_reply_tx,
                                notification_id,
                                pb::NotificationReplyCode::Ok,
                                payload,
                            )
                            .await;
                        }
                    }
                }
            })
        }
        "downloader" => {
            let interval = data.task_interval();
            let data = data.clone();
            let notify_enabled = serde_json::from_value::<DownloaderTaskConfig>(data.clone())
                .map(|cfg| cfg.notify.enabled)
                .unwrap_or(false);
            tokio::spawn(async move {
                loop {
                    if notify_enabled {
                        let (code, payload) = match run_downloader_once(&data).await {
                            Ok(payload) => (pb::NotificationReplyCode::Ok, payload.to_string()),
                            Err(err) => (
                                pb::NotificationReplyCode::Error,
                                serde_json::json!({
                                    "Task": "downloader",
                                    "Error": err.to_string(),
                                })
                                .to_string(),
                            ),
                        };
                        send_task_reply(&task_reply_tx, notification_id, code, payload).await;
                    } else if let Err(err) = run_downloader_once(&data).await {
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
            let interval = data.task_interval();
            let data = data.clone();
            let use_schedule = data.has_ioc_schedule();
            tokio::spawn(async move {
                let mut last_schedule_second = -1_i64;
                loop {
                    if use_schedule {
                        let now = time::OffsetDateTime::now_utc();
                        let now_second = now.unix_timestamp();
                        if data.ioc_schedule_matches_now(now) && now_second != last_schedule_second
                        {
                            let (code, payload) = match run_ioc_scanner_once(&data).await {
                                Ok(payload) => (pb::NotificationReplyCode::Ok, payload.to_string()),
                                Err(err) => (
                                    pb::NotificationReplyCode::Error,
                                    serde_json::json!({
                                        "Task": "ioc-scanner",
                                        "Error": err.to_string(),
                                    })
                                    .to_string(),
                                ),
                            };
                            send_task_reply(&task_reply_tx, notification_id, code, payload).await;
                            last_schedule_second = now_second;
                        }

                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                        }
                        continue;
                    }

                    let (code, payload) = match run_ioc_scanner_once(&data).await {
                        Ok(payload) => (pb::NotificationReplyCode::Ok, payload.to_string()),
                        Err(err) => (
                            pb::NotificationReplyCode::Error,
                            serde_json::json!({
                                "Task": "ioc-scanner",
                                "Error": err.to_string(),
                            })
                            .to_string(),
                        ),
                    };
                    send_task_reply(&task_reply_tx, notification_id, code, payload).await;

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
                send_task_reply(
                    &task_reply_tx,
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

async fn run_downloader_once(data: &Value) -> Result<Value> {
    let cfg: DownloaderTaskConfig = serde_json::from_value(data.clone())?;
    let timeout = cfg
        .timeout
        .parse_or_default(std::time::Duration::from_secs(5));
    let client = reqwest::Client::builder().timeout(timeout).build()?;

    let mut sources = 0usize;
    let mut updated = 0usize;
    let mut failed = 0usize;
    let mut errors = Vec::new();

    for source in cfg.urls.into_iter().filter(|source| source.enabled) {
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

async fn run_ioc_scanner_once(data: &Value) -> Result<Value> {
    let cfg: IocScannerTaskConfig = serde_json::from_value(data.clone())?;
    let global_timeout = cfg
        .timeout
        .parse_or_default(std::time::Duration::from_secs(30));
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string());

    let mut reports = Vec::new();

    for tool in cfg.tools.into_iter().filter(|tool| tool.enabled) {
        if tool.cmd.is_empty() || tool.cmd[0].trim().is_empty() {
            continue;
        }

        let timeout = tool
            .options
            .max_running_time
            .parse_or_default(global_timeout);
        let started_at = std::time::Instant::now();
        let command = tool.cmd[0].clone();
        let args = tool.cmd.iter().skip(1).cloned().collect::<Vec<_>>();

        let output_result = tokio::time::timeout(timeout, async {
            tokio::process::Command::new(&command)
                .args(&args)
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
                let trimmed = if merged.chars().count() <= 8192 {
                    merged.clone()
                } else {
                    merged
                        .chars()
                        .take(8192)
                        .collect::<String>()
                        .trim_end()
                        .to_string()
                };

                if let Err(err) = write_ioc_report_files(&tool, &html_report).await {
                    tracing::debug!(tool = %tool.name, "failed to write IOC report files: {err}");
                }

                reports.push(serde_json::json!({
                    "Tool": tool.name,
                    "Command": command,
                    "Args": args,
                    "ExitCode": output.status.code().unwrap_or(-1),
                    "Status": if output.status.success() { "ok" } else { "error" },
                    "DurationMs": started_at.elapsed().as_millis() as u64,
                    "Report": trimmed.replace('\n', "<br>"),
                }));
            }
            Ok(Err(err)) => {
                reports.push(serde_json::json!({
                    "Tool": tool.name,
                    "Command": command,
                    "Args": args,
                    "Status": "error",
                    "DurationMs": started_at.elapsed().as_millis() as u64,
                    "Report": format!("failed to execute command: {err}"),
                }));
            }
            Err(_) => {
                reports.push(serde_json::json!({
                    "Tool": tool.name,
                    "Command": command,
                    "Args": args,
                    "Status": "timeout",
                    "DurationMs": started_at.elapsed().as_millis() as u64,
                    "Report": format!("timed out after {}ms", timeout.as_millis()),
                }));
            }
        }
    }

    let tools_ran = reports.len();

    Ok(serde_json::json!({
        "Task": "ioc-scanner",
        "Host": hostname,
        "Tools": reports,
        "ToolsRan": tools_ran,
    }))
}

async fn write_ioc_report_files(tool: &IocToolConfig, report: &str) -> Result<()> {
    for report_cfg in
        tool.options.reports.iter().filter(|cfg| {
            cfg.r#type.trim().eq_ignore_ascii_case("file") && !cfg.path.trim().is_empty()
        })
    {
        let report_path = report_cfg.build_report_path(tool)?;
        if let Some(parent) = report_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(report_path, report).await?;
    }

    Ok(())
}

pub(crate) async fn send_task_reply(
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    notification_id: u64,
    code: pb::NotificationReplyCode,
    data: String,
) {
    let reply_id = if notification_id == 0 {
        let synthetic_id = next_disk_task_reply_id();
        match code {
            pb::NotificationReplyCode::Ok => {
                tracing::info!(reply_id = synthetic_id, task_data = %data, "disk task output");
            }
            _ => {
                tracing::error!(reply_id = synthetic_id, task_data = %data, "disk task error");
            }
        }
        synthetic_id
    } else {
        notification_id
    };

    let _ = task_reply_tx
        .send(pb::NotificationReply {
            id: reply_id,
            code: code as i32,
            data,
        })
        .await;
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

pub(crate) fn validate_task_start_input(task_name: &str, data: &Value) -> Result<(), String> {
    let normalized = task_name.normalized_task_name();

    if matches!(
        normalized.as_str(),
        "pid-monitor"
            | "node-monitor"
            | "sockets-monitor"
            | "looper"
            | "downloader"
            | "ioc-scanner"
    ) && let Some(raw_interval) = data.data_string("interval")
        && !raw_interval.trim().is_empty()
        && raw_interval.trim().parse_task_interval().is_none()
    {
        return Err(format!("invalid interval for {normalized}"));
    }

    if normalized != "pid-monitor" {
        if normalized == "node-monitor" {
            if data
                .data_or_suffix("node", task_name, "node-monitor")
                .is_none()
            {
                return Err("invalid node for node-monitor".to_string());
            }
            return Ok(());
        }

        if normalized == "sockets-monitor" {
            for key in ["family", "proto", "state"] {
                if data.data_u8(key).is_none() {
                    return Err(format!("invalid sockets-monitor config: missing {key}"));
                }
            }
            return Ok(());
        }

        return Ok(());
    }

    let Some(pid_raw) = data.data_or_suffix("pid", task_name, "pid-monitor") else {
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

pub(crate) fn is_runtime_task_name_supported(task_name: &str) -> bool {
    task_name.is_runtime_task_name_supported()
}

async fn fetch_iface_name_map_rtnetlink() -> Option<HashMap<u32, String>> {
    let (connection, handle, _) = rtnetlink::new_connection().ok()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    let mut map = HashMap::new();

    while let Some(msg) = links.next().await {
        let Ok(link) = msg else {
            continue;
        };

        for attr in link.attributes {
            if let LinkAttribute::IfName(name) = attr {
                map.insert(link.header.index as u32, name);
                break;
            }
        }
    }

    Some(map)
}

fn resolve_iface_name_sysfs(index: u32) -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let ifindex_path = entry.path().join("ifindex");
        let Ok(value) = std::fs::read_to_string(ifindex_path) else {
            continue;
        };
        let Ok(ifindex) = value.trim().parse::<u32>() else {
            continue;
        };
        if ifindex == index {
            return Some(name);
        }
    }
    None
}

fn read_proc_net_packet_rows() -> Vec<ProcNetPacketRow> {
    let Ok(contents) = std::fs::read_to_string("/proc/net/packet") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }

        let proto = u16::from_str_radix(cols[3], 16).unwrap_or(nix::libc::IPPROTO_RAW as u16);
        let iface = cols[4].parse::<u32>().unwrap_or(0);
        let uid = cols[7].parse::<u32>().unwrap_or(0);
        let inode = cols[8].parse::<u32>().unwrap_or(0);
        out.push(ProcNetPacketRow {
            proto,
            iface,
            uid,
            inode,
        });
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
        let cols: Vec<&str> = line.split_whitespace().collect();
        let Some(inode_pos) = inode_idx else {
            continue;
        };
        let Some(uid_pos) = uid_idx else {
            continue;
        };
        let Some(if_pos) = iface_idx else {
            continue;
        };

        if cols.len() <= inode_pos || cols.len() <= uid_pos || cols.len() <= if_pos {
            continue;
        }

        let inode = cols[inode_pos].parse::<u32>().unwrap_or(0);
        let uid = cols[uid_pos].parse::<u32>().unwrap_or(0);
        let iface = cols[if_pos].parse::<u32>().unwrap_or(0);

        let (cookie0, cookie1) = if let Some(cookie_pos) = cookie_idx {
            if cols.len() > cookie_pos {
                let raw = cols[cookie_pos].trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(raw, 16) {
                    ((v & 0xffff_ffff) as u32, ((v >> 32) & 0xffff_ffff) as u32)
                } else {
                    (0, 0)
                }
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

const AF_XDP_FAMILY: u8 = 44;

#[cfg(test)]
mod tests {
    use super::{
        DISK_TASK_REPLY_ID_BASE, DiskTaskRuntime, IocTaskDataExt, IocTimeSpecExt,
        TaskIntervalSpecExt, TaskNameExt, build_task_key, is_runtime_task_name_supported,
        send_task_reply, stop_disk_tasks, stop_runtime_tasks, validate_task_start_input,
    };
    use opensnitch_proto::pb;
    use serde_json::json;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn normalize_task_name_accepts_legacy_aliases() {
        assert_eq!("pidmonitor".normalized_task_name(), "pid-monitor");
        assert_eq!("nodemonitor".normalized_task_name(), "node-monitor");
        assert_eq!("socketsmonitor".normalized_task_name(), "sockets-monitor");
        assert_eq!("iocscanner".normalized_task_name(), "ioc-scanner");
        assert_eq!("looptask".normalized_task_name(), "looper");
        assert_eq!("  PID-MONITOR  ".normalized_task_name(), "pid-monitor");
        assert_eq!("pid-monitor-123".normalized_task_name(), "pid-monitor");
        assert_eq!("node-monitor-main".normalized_task_name(), "node-monitor");
        assert_eq!(
            "socketsmonitor-debug".normalized_task_name(),
            "sockets-monitor"
        );
        assert_eq!("iocscanner-weekly".normalized_task_name(), "ioc-scanner");
        assert_eq!("downloader-list-a".normalized_task_name(), "downloader");
    }

    #[test]
    fn build_task_key_normalizes_aliases_and_uses_identity_keys() {
        assert_eq!(
            build_task_key("pidmonitor", &json!({ "pid": "4242" })),
            "pid-monitor:4242"
        );
        assert_eq!(
            build_task_key("nodemonitor", &json!({ "node": "alpha" })),
            "node-monitor:alpha"
        );
        assert_eq!(
            build_task_key("socketsmonitor", &json!({})),
            "sockets-monitor"
        );
    }

    #[test]
    fn build_task_key_defaults_node_monitor_key_when_node_missing() {
        assert_eq!(
            build_task_key("node-monitor", &json!({})),
            "node-monitor:default"
        );
    }

    #[test]
    fn build_task_key_uses_instance_suffix_when_data_is_missing() {
        assert_eq!(
            build_task_key("pid-monitor-4242", &json!({})),
            "pid-monitor:4242"
        );
        assert_eq!(
            build_task_key("node-monitor-main", &json!({})),
            "node-monitor:main"
        );
        assert_eq!(
            build_task_key("pidmonitor-555", &json!({})),
            "pid-monitor:555"
        );
        assert_eq!(
            build_task_key("nodemonitor-edge", &json!({})),
            "node-monitor:edge"
        );
    }

    #[test]
    fn validate_task_start_input_checks_pid_monitor_inputs() {
        assert!(validate_task_start_input("node-monitor", &json!({ "node": "main" })).is_ok());

        let invalid = validate_task_start_input("pid-monitor", &json!({"pid": "abc"}));
        assert!(invalid.is_err());

        let invalid_interval = validate_task_start_input(
            "pid-monitor",
            &json!({"pid": std::process::id().to_string(), "interval": "bogus"}),
        );
        assert!(invalid_interval.is_err());

        let running_pid = std::process::id().to_string();
        let from_data = validate_task_start_input("pid-monitor", &json!({"pid": running_pid}));
        assert!(from_data.is_ok());

        let from_suffix =
            validate_task_start_input(&format!("pid-monitor-{}", std::process::id()), &json!({}));
        assert!(from_suffix.is_ok());

        let node_missing = validate_task_start_input("node-monitor", &json!({}));
        assert!(node_missing.is_err());

        let sockets_missing =
            validate_task_start_input("sockets-monitor", &json!({"family": 2, "proto": 6}));
        assert!(sockets_missing.is_err());

        let sockets_ok = validate_task_start_input(
            "sockets-monitor",
            &json!({"family": 2, "proto": 6, "state": 1}),
        );
        assert!(sockets_ok.is_ok());
    }

    #[test]
    fn parse_task_interval_parses_supported_units() {
        assert_eq!(
            "250ms".parse_task_interval(),
            Some(std::time::Duration::from_millis(250))
        );
        assert_eq!(
            "5s".parse_task_interval(),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(
            "2m".parse_task_interval(),
            Some(std::time::Duration::from_secs(120))
        );
        assert_eq!(
            "1h".parse_task_interval(),
            Some(std::time::Duration::from_secs(3600))
        );
        assert!("oops".parse_task_interval().is_none());
    }

    #[test]
    fn ioc_schedule_time_matches_hh_mm_and_hh_mm_ss() {
        assert!("09:15".matches_ioc_time(9, 15, 0));
        assert!("09:15:30".matches_ioc_time(9, 15, 30));
        assert!(!"09:15".matches_ioc_time(9, 15, 31));
        assert!(!"bad".matches_ioc_time(9, 15, 0));
    }

    #[test]
    fn ioc_schedule_matches_now_from_time_entry() {
        let data = json!({
            "schedule": [
                {
                    "weekday": [1],
                    "time": ["11:22:33"]
                }
            ]
        });

        let now = time::Date::from_calendar_date(2026, time::Month::April, 6)
            .expect("valid date")
            .with_hms(11, 22, 33)
            .expect("valid time")
            .assume_utc();
        assert!(data.ioc_schedule_matches_now(now));
    }

    #[test]
    fn ioc_schedule_matches_now_from_hour_minute_second_arrays() {
        let data = json!({
            "schedule": [
                {
                    "weekday": [2],
                    "hour": [14],
                    "minute": [9],
                    "second": [7]
                }
            ]
        });

        let now = time::Date::from_calendar_date(2026, time::Month::April, 7)
            .expect("valid date")
            .with_hms(14, 9, 7)
            .expect("valid time")
            .assume_utc();
        assert!(data.ioc_schedule_matches_now(now));
    }

    #[test]
    fn is_supported_task_name_accepts_known_aliases_only() {
        assert!(is_runtime_task_name_supported("pidmonitor"));
        assert!(is_runtime_task_name_supported("node-monitor-main"));
        assert!(is_runtime_task_name_supported("socketsmonitor"));
        assert!(!is_runtime_task_name_supported("downloader-list-a"));
        assert!(!is_runtime_task_name_supported("unknown-task"));

        assert!("downloader-list-a".is_disk_task_name_supported());
        assert!("looptask".is_disk_task_name_supported());
        assert!("iocscanner-weekly".is_disk_task_name_supported());
        assert!(!"pid-monitor-123".is_disk_task_name_supported());
    }

    #[tokio::test]
    async fn stop_runtime_tasks_cancels_all_handles() {
        let first = CancellationToken::new();
        let second = CancellationToken::new();
        let first_child = first.clone();
        let second_child = second.clone();

        let mut handles = std::collections::HashMap::from([
            (
                "pid-monitor:1".to_string(),
                (
                    tokio::spawn(async move {
                        first_child.cancelled().await;
                    }),
                    first,
                ),
            ),
            (
                "node-monitor:alpha".to_string(),
                (
                    tokio::spawn(async move {
                        second_child.cancelled().await;
                    }),
                    second,
                ),
            ),
        ]);

        assert_eq!(stop_runtime_tasks(&mut handles), 2);
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn stop_disk_tasks_cancels_all_handles() {
        let token = CancellationToken::new();
        let token_child = token.clone();
        let mut handles = std::collections::HashMap::from([(
            "disk-task:downloader".to_string(),
            DiskTaskRuntime {
                handle: tokio::spawn(async move {
                    token_child.cancelled().await;
                }),
                token,
                fingerprint: "abc123".to_string(),
            },
        )]);

        assert_eq!(stop_disk_tasks(&mut handles), 1);
        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn send_task_reply_assigns_synthetic_id_for_disk_tasks() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(1);

        send_task_reply(&tx, 0, pb::NotificationReplyCode::Ok, "disk payload".to_string()).await;

        let reply = rx.recv().await.expect("reply should be sent");
        assert!(reply.id >= DISK_TASK_REPLY_ID_BASE);
        assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
        assert_eq!(reply.data, "disk payload");
    }

    #[tokio::test]
    async fn send_task_reply_keeps_existing_notification_id() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<pb::NotificationReply>(1);

        send_task_reply(&tx, 77, pb::NotificationReplyCode::Error, "oops".to_string()).await;

        let reply = rx.recv().await.expect("reply should be sent");
        assert_eq!(reply.id, 77);
        assert_eq!(reply.code, pb::NotificationReplyCode::Error as i32);
        assert_eq!(reply.data, "oops");
    }
}

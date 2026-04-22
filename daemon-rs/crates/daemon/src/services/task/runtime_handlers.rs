use std::{collections::HashMap, fmt::Display, sync::Arc};

use anyhow::Result;
use opensnitch_proto::pb;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::{
    TaskService, naming as task_runtime_naming, reply as task_runtime_reply, socket_monitor,
};
use crate::{
    models::{
        task_config::{
            DownloaderTaskConfig, IocReportConfig, IocScannerTaskConfig, IocScheduleConfig,
            IocToolConfig,
        },
        task_wire::TaskErrorPayload,
    },
    platform::ports::socket_diag_port::NativeSocketDiagPort,
    services::{process::ProcessService, storage::StorageService},
    utils::{
        duration_parse::{TASK_INTERVAL_OPTIONS, parse_human_duration},
        json_value,
        name_parsing::case_folded,
        proc_fs::proc_sys_kernel_value,
        proc_net::{read_proc_net_packet_rows, read_proc_net_xdp_rows},
        time_spec::matches_hms_spec,
    },
};

impl TaskService {
    async fn wait_periodic_tick(
        token: &CancellationToken,
        interval: std::time::Duration,
        first_run: &mut bool,
    ) -> bool {
        if *first_run {
            *first_run = false;
            return !token.is_cancelled();
        }

        tokio::select! {
            _ = token.cancelled() => false,
            _ = tokio::time::sleep(interval) => !token.is_cancelled(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
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
}

impl TaskService {
    fn task_interval(data: &Value) -> std::time::Duration {
        let raw =
            json_value::field_string_or_u64(data, "interval").unwrap_or_else(|| "5s".to_string());
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return std::time::Duration::from_secs(5);
        }
        parse_human_duration(trimmed, TASK_INTERVAL_OPTIONS)
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

        if entry
            .time
            .iter()
            .any(|value| matches_hms_spec(value.as_str(), now.hour(), now.minute(), now.second()))
        {
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
        parse_human_duration(trimmed, TASK_INTERVAL_OPTIONS).unwrap_or(default)
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
            return task_runtime_reply::DOWNLOADER_SUCCESS_MSG.to_string();
        };

        let mut message = String::from(task_runtime_reply::DOWNLOADER_SUCCESS_MSG);
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
            task_runtime_reply::DOWNLOADER_SUCCESS_MSG.to_string()
        }
    }

    fn emit_legacy_downloader_typed_result(data: &str) {
        // Go parity: downloader emits a second typed TaskResults payload
        // (Type=9999) that the default UI task-event monitor ignores.
        let legacy = task_runtime_reply::build_legacy_downloader_task_result(data);
        tracing::debug!(target: "opensnitch.task", task = task_runtime_naming::TASK_DOWNLOADER, legacy_task_result = %legacy, "emitting legacy typed task result");
    }

    fn task_error_message(task_name: &str, err: impl Display) -> String {
        format!("{task_name} error: {err}")
    }

    fn task_error_payload(task_name: &str, err: impl Display) -> String {
        serde_json::to_string(&TaskErrorPayload::new(task_name, err.to_string()))
            .unwrap_or_else(|_| format!("{{\"Task\":\"{}\",\"Error\":\"{}\"}}", task_name, err))
    }

    async fn emit_task_ok(
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        task_name: &str,
        notification_id: u64,
        data: String,
    ) {
        Self::send_task_event(
            task_reply_tx,
            task_name,
            notification_id,
            pb::NotificationReplyCode::Ok,
            data,
        )
        .await;
    }

    async fn emit_task_error(
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        task_name: &str,
        notification_id: u64,
        data: String,
    ) {
        Self::send_task_event(
            task_reply_tx,
            task_name,
            notification_id,
            pb::NotificationReplyCode::Error,
            data,
        )
        .await;
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
        let task_name = task_runtime_naming::normalized_task_name(task_name);
        match task_name.as_str() {
            task_runtime_naming::TASK_PID_MONITOR => {
                let pid = task_runtime_naming::data_or_suffix(
                    data.as_ref(),
                    "pid",
                    &raw_task_name,
                    task_runtime_naming::TASK_PID_MONITOR,
                )
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
                let interval = Self::task_interval(data.as_ref());
                tokio::spawn(async move {
                    let mut first_run = true;
                    if pid == 0 {
                        Self::emit_task_error(
                            &task_reply_tx,
                            task_runtime_naming::TASK_PID_MONITOR,
                            notification_id,
                            "invalid pid for pid-monitor".to_string(),
                        )
                        .await;
                        return;
                    }
                    loop {
                        if !Self::wait_periodic_tick(&token, interval, &mut first_run).await {
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
                                    tracing::debug!(task = task_runtime_naming::TASK_PID_MONITOR, pid, data = %raw, "task result");
                                    Self::emit_task_ok(
                                        &task_reply_tx,
                                        task_runtime_naming::TASK_PID_MONITOR,
                                        notification_id,
                                        raw,
                                    )
                                    .await;
                                }
                            }
                            Err(err) => {
                                let message = Self::task_error_message(
                                    task_runtime_naming::TASK_PID_MONITOR,
                                    &err,
                                );
                                Self::emit_task_error(
                                    &task_reply_tx,
                                    task_runtime_naming::TASK_PID_MONITOR,
                                    notification_id,
                                    message,
                                )
                                .await;
                                tracing::debug!(
                                    task = task_runtime_naming::TASK_PID_MONITOR,
                                    pid,
                                    "task error: {err}"
                                );
                                break;
                            }
                        }
                    }
                })
            }
            task_runtime_naming::TASK_NODE_MONITOR => {
                let node = task_runtime_naming::data_or_suffix(
                    data.as_ref(),
                    "node",
                    &raw_task_name,
                    task_runtime_naming::TASK_NODE_MONITOR,
                )
                .unwrap_or_default();
                let interval = Self::task_interval(data.as_ref());
                tokio::spawn(async move {
                    let mut first_run = true;
                    loop {
                        if !Self::wait_periodic_tick(&token, interval, &mut first_run).await {
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
                        Self::emit_task_ok(
                            &task_reply_tx,
                            task_runtime_naming::TASK_NODE_MONITOR,
                            notification_id,
                            payload,
                        )
                        .await;
                        tracing::debug!(
                            task = task_runtime_naming::TASK_NODE_MONITOR,
                            node,
                            "task result"
                        );
                    }
                })
            }
            task_runtime_naming::TASK_SOCKETS_MONITOR => {
                let interval = Self::task_interval(data.as_ref());
                let family = json_value::field_u8(data.as_ref(), "family")
                    .unwrap_or(nix::libc::AF_INET as u8);
                let proto = json_value::field_u8(data.as_ref(), "proto")
                    .unwrap_or(nix::libc::IPPROTO_TCP as u8);
                let state_filter = json_value::field_u8(data.as_ref(), "state").unwrap_or(0);
                tokio::spawn(async move {
                    let mut first_run = true;
                    loop {
                        if !Self::wait_periodic_tick(&token, interval, &mut first_run).await {
                            break;
                        }

                        match NativeSocketDiagPort::dump_sockets_async(family, proto).await {
                            Ok(sockets) => {
                                let mut inode_pid_cache: HashMap<u32, Option<u32>> = HashMap::new();
                                let mut iface_cache: HashMap<u32, String> = HashMap::new();
                                let rtnl_iface_map =
                                    socket_monitor::fetch_iface_name_map_rtnetlink().await;
                                let mut process_map =
                                    serde_json::Map::<String, serde_json::Value>::new();
                                let mut table = Vec::with_capacity(sockets.len());

                                for s in &sockets {
                                    if !(state_filter == 0 || state_filter == s.state) {
                                        continue;
                                    }

                                    let (pid, iface_name) =
                                        socket_monitor::prepare_socket_monitor_row(
                                            &process,
                                            &mut process_map,
                                            &mut inode_pid_cache,
                                            &mut iface_cache,
                                            rtnl_iface_map.as_ref(),
                                            s.inode,
                                            s.iface,
                                        )
                                        .await;

                                    table.push(socket_monitor::socket_monitor_diag_row_json(
                                        s,
                                        iface_name,
                                        pid,
                                        proto.into(),
                                    ));
                                }

                                if (family == 0 || family == nix::libc::AF_PACKET as u8)
                                    && state_filter == 0
                                {
                                    for pkt in read_proc_net_packet_rows() {
                                        let (pid, iface_name) =
                                            socket_monitor::prepare_socket_monitor_row(
                                                &process,
                                                &mut process_map,
                                                &mut inode_pid_cache,
                                                &mut iface_cache,
                                                rtnl_iface_map.as_ref(),
                                                pkt.inode,
                                                pkt.iface,
                                            )
                                            .await;

                                        table.push(socket_monitor::socket_monitor_packet_row_json(
                                            &pkt, iface_name, pid,
                                        ));
                                    }
                                }

                                if (family == 0 || family == socket_monitor::AF_XDP_FAMILY)
                                    && state_filter == 0
                                {
                                    for xdp in read_proc_net_xdp_rows() {
                                        let (pid, iface_name) =
                                            socket_monitor::prepare_socket_monitor_row(
                                                &process,
                                                &mut process_map,
                                                &mut inode_pid_cache,
                                                &mut iface_cache,
                                                rtnl_iface_map.as_ref(),
                                                xdp.inode,
                                                xdp.iface,
                                            )
                                            .await;

                                        table.push(socket_monitor::socket_monitor_xdp_row_json(
                                            &xdp, iface_name, pid,
                                        ));
                                    }
                                }

                                let payload = serde_json::json!({
                                    "Table": table,
                                    "Processes": process_map,
                                })
                                .to_string();
                                Self::emit_task_ok(
                                    &task_reply_tx,
                                    task_runtime_naming::TASK_SOCKETS_MONITOR,
                                    notification_id,
                                    payload,
                                )
                                .await;
                                tracing::debug!(
                                    task = task_runtime_naming::TASK_SOCKETS_MONITOR,
                                    family,
                                    proto,
                                    count = sockets.len(),
                                    "task result"
                                );
                            }
                            Err(err) => {
                                let message = Self::task_error_message(
                                    task_runtime_naming::TASK_SOCKETS_MONITOR,
                                    &err,
                                );
                                Self::emit_task_error(
                                    &task_reply_tx,
                                    task_runtime_naming::TASK_SOCKETS_MONITOR,
                                    notification_id,
                                    message,
                                )
                                .await;
                                tracing::debug!(
                                    task = task_runtime_naming::TASK_SOCKETS_MONITOR,
                                    family,
                                    proto,
                                    "task error: {err}"
                                );
                            }
                        }
                    }
                })
            }
            task_runtime_naming::TASK_LOOPER => {
                let interval_raw = json_value::field_string_or_u64(data.as_ref(), "interval")
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
                                Self::emit_task_ok(
                                    &task_reply_tx,
                                    task_runtime_naming::TASK_LOOPER,
                                    notification_id,
                                    interval_raw.clone(),
                                )
                                .await;
                            }
                        }
                    }
                })
            }
            task_runtime_naming::TASK_DOWNLOADER => {
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
                        Self::dispatch_downloader_result(
                            &task_reply_tx,
                            notification_id,
                            notify_enabled,
                            run_result,
                        )
                        .await;

                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = tokio::time::sleep(interval) => {}
                        }
                    }
                })
            }
            task_runtime_naming::TASK_IOC_SCANNER => {
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
                                    TaskService::ioc_schedule_matches_now_cfg(cfg.as_ref(), now)
                                })
                                .unwrap_or(false)
                                && now_second != last_schedule_second
                            {
                                let run_result = if let Some(cfg) = ioc_cfg.as_ref() {
                                    Self::run_ioc_scanner_once_cfg(cfg.as_ref()).await
                                } else {
                                    Err(anyhow::anyhow!("invalid ioc-scanner config"))
                                };

                                Self::emit_ioc_scan_results(
                                    &task_reply_tx,
                                    notification_id,
                                    run_result,
                                )
                                .await;
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
                    Self::emit_task_error(
                        &task_reply_tx,
                        task_name.as_str(),
                        notification_id,
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
        task_runtime_reply::send_task_event(
            task_reply_tx,
            None,
            None,
            task_name,
            notification_id,
            code,
            data,
        )
        .await;
    }

    async fn dispatch_downloader_result(
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        notification_id: u64,
        notify_enabled: bool,
        run_result: Result<Value>,
    ) {
        if !notify_enabled {
            if let Err(err) = run_result {
                tracing::debug!("downloader run completed with non-fatal error: {err}");
            }
            return;
        }
        let (payload, ok) = match run_result {
            Ok(value) => (Self::downloader_go_result_message(&value), true),
            Err(err) => (
                Self::task_error_payload(task_runtime_naming::TASK_DOWNLOADER, &err),
                false,
            ),
        };
        let legacy_payload = payload.clone();
        if ok {
            Self::emit_task_ok(
                task_reply_tx,
                task_runtime_naming::TASK_DOWNLOADER,
                notification_id,
                payload,
            )
            .await;
        } else {
            Self::emit_task_error(
                task_reply_tx,
                task_runtime_naming::TASK_DOWNLOADER,
                notification_id,
                payload,
            )
            .await;
        }
        Self::emit_legacy_downloader_typed_result(&legacy_payload);
    }

    async fn emit_ioc_scan_results(
        task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
        notification_id: u64,
        run_result: Result<Vec<String>>,
    ) {
        match run_result {
            Ok(payloads) => {
                for payload in payloads {
                    Self::emit_task_ok(
                        task_reply_tx,
                        task_runtime_naming::TASK_IOC_SCANNER,
                        notification_id,
                        payload,
                    )
                    .await;
                }
            }
            Err(err) => {
                let payload = Self::task_error_payload(task_runtime_naming::TASK_IOC_SCANNER, &err);
                Self::emit_task_error(
                    task_reply_tx,
                    task_runtime_naming::TASK_IOC_SCANNER,
                    notification_id,
                    payload,
                )
                .await;
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
            let download_result = async {
                let response = client.get(source.remote.trim()).send().await?;
                if !response.status().is_success() {
                    anyhow::bail!("http status {}", response.status().as_u16());
                }

                let body = response.bytes().await?;
                if body.is_empty() {
                    anyhow::bail!("empty response body");
                }

                StorageService::global()
                    .write_bytes_to_path_and_notify("task", &local_path, body.as_ref())
                    .await?;
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
            "Task": task_runtime_naming::TASK_DOWNLOADER,
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
        let hostname =
            proc_sys_kernel_value("hostname").unwrap_or_else(|| "unknown-host".to_string());

        let mut reports = Vec::new();
        let mut tools_ran = 0usize;

        for tool in cfg.tools.iter().filter(|tool| tool.enabled) {
            if tool.cmd.is_empty() || tool.cmd[0].trim().is_empty() {
                continue;
            }

            tools_ran = tools_ran.saturating_add(1);

            let timeout =
                Self::parse_interval_or_default(&tool.options.max_running_time, global_timeout);
            reports.push(Self::run_ioc_tool_report(tool, timeout, &hostname).await?);
        }

        if tools_ran == 0 {
            anyhow::bail!("no tools configured");
        }

        Ok(reports)
    }

    async fn run_ioc_tool_report(
        tool: &IocToolConfig,
        timeout: std::time::Duration,
        hostname: &str,
    ) -> Result<String> {
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

                if let Err(err) = Self::write_ioc_report_files(tool, &html_report).await {
                    tracing::debug!(tool = %tool.name, "failed to write IOC report files: {err}");
                }

                let started_human = time::OffsetDateTime::now_utc();
                let stamp_format = time::format_description::parse(
                    "[day]-[month]-[year], [hour]:[minute]:[second]",
                )?;
                let started_stamp = started_human.format(&stamp_format)?;
                let duration = started_at.elapsed().as_secs();

                Ok(format!(
                    "==== {} - {} ({}) ====\n\n{}\n\n=== {} - ({}s) ===",
                    tool.name, hostname, started_stamp, merged, tool.name, duration
                )
                .replace('\n', "<br>"))
            }
            Ok(Err(err)) => Ok(format!("{}: failed to execute command: {err}", tool.name)),
            Err(_) => Ok(format!(
                "{}: timed out after {}ms",
                tool.name,
                timeout.as_millis()
            )),
        }
    }

    async fn write_ioc_report_files(tool: &IocToolConfig, report: &str) -> Result<()> {
        for report_cfg in
            tool.options.reports.iter().filter(|cfg| {
                case_folded(cfg.r#type.trim()) == "file" && !cfg.path.trim().is_empty()
            })
        {
            let report_path = Self::build_report_path(report_cfg, tool)?;
            StorageService::global()
                .write_bytes_to_path_and_notify("task", &report_path, report.as_bytes())
                .await?;
        }

        Ok(())
    }
}

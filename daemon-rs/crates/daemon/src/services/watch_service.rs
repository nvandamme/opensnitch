use opensnitch_proto::pb;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    commands::task_runtime,
    config::ProcMonitorMethod,
    models::rule_storage::{RuleFile, RuleFileOperator},
    models::ui_alert::{UiAlert, enqueue_alert},
    services::{
        config_service::ConfigService, firewall_service::FirewallService,
        process_service::ProcessService, rule_service::RuleService, stats_service::StatsService,
    },
};

pub(crate) type ProcWorkerReconfigure = Arc<
    dyn Fn(Option<ProcMonitorMethod>) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct WatchService {
    shutdown: CancellationToken,
    config: ConfigService,
    rules: RuleService,
    firewall: FirewallService,
    stats: StatsService,
    process: ProcessService,
    task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
    alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
    reconfigure_proc_workers: ProcWorkerReconfigure,
}

impl WatchService {
    pub fn new(
        shutdown: CancellationToken,
        config: ConfigService,
        rules: RuleService,
        firewall: FirewallService,
        stats: StatsService,
        process: ProcessService,
        task_reply_tx: tokio::sync::mpsc::Sender<pb::NotificationReply>,
        alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
        reconfigure_proc_workers: ProcWorkerReconfigure,
    ) -> Self {
        Self {
            shutdown,
            config,
            rules,
            firewall,
            stats,
            process,
            task_reply_tx,
            alert_tx,
            reconfigure_proc_workers,
        }
    }

    pub(crate) fn parse_firewall_monitor_interval(raw: &str) -> std::time::Duration {
        let value = raw.trim();
        if value.is_empty() {
            return std::time::Duration::from_secs(10);
        }

        if value == "0" {
            return std::time::Duration::ZERO;
        }

        if let Some(ms) = value.strip_suffix("ms")
            && let Ok(parsed) = ms.trim().parse::<u64>()
        {
            return std::time::Duration::from_millis(parsed);
        }
        if let Some(s) = value.strip_suffix('s')
            && let Ok(parsed) = s.trim().parse::<u64>()
        {
            return std::time::Duration::from_secs(parsed);
        }
        if let Some(m) = value.strip_suffix('m')
            && let Ok(parsed) = m.trim().parse::<u64>()
        {
            return std::time::Duration::from_secs(parsed.saturating_mul(60));
        }
        if let Some(h) = value.strip_suffix('h')
            && let Ok(parsed) = h.trim().parse::<u64>()
        {
            return std::time::Duration::from_secs(parsed.saturating_mul(3600));
        }

        std::time::Duration::from_secs(10)
    }

    pub(crate) fn should_forward_inotify_mask(mask: u32) -> bool {
        let watched = nix::libc::IN_CREATE
            | nix::libc::IN_MODIFY
            | nix::libc::IN_DELETE
            | nix::libc::IN_MOVED_FROM
            | nix::libc::IN_MOVED_TO
            | nix::libc::IN_CLOSE_WRITE
            | nix::libc::IN_DELETE_SELF
            | nix::libc::IN_MOVE_SELF;

        (mask & watched) != 0
    }

    fn watch_targets(path: &std::path::Path) -> Vec<PathBuf> {
        let mut targets = Vec::new();
        if path.exists() {
            targets.push(path.to_path_buf());
        }
        if let Some(parent) = path.parent() {
            targets.push(parent.to_path_buf());
        }
        targets.sort();
        targets.dedup();
        targets
    }

    fn proc_monitor_label(method: crate::config::ProcMonitorMethod) -> &'static str {
        match method {
            crate::config::ProcMonitorMethod::Proc => "/proc",
            crate::config::ProcMonitorMethod::Audit => "audit",
            crate::config::ProcMonitorMethod::Ebpf => "ebpf",
        }
    }

    fn format_rule_operator(operator: &pb::Operator) -> String {
        if !operator.list.is_empty() {
            let mut out = String::new();
            for (idx, item) in operator.list.iter().enumerate() {
                if idx > 0 {
                    out.push_str(" and ");
                }
                out.push_str(&Self::format_rule_operator(item));
            }
            return out;
        }

        if operator.operand.is_empty() {
            return operator.data.clone();
        }

        if operator.data.is_empty() {
            return operator.operand.clone();
        }

        format!("{} is '{}'", operator.operand, operator.data)
    }

    fn format_deleted_rule(rule: &pb::Rule) -> String {
        let state = if rule.enabled { "Enabled" } else { "Disabled" };
        let condition = rule
            .operator
            .as_ref()
            .map(Self::format_rule_operator)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "true".to_string());
        format!(
            "Delete() rule: [{}] {}: if({}){{ {} {} }}",
            state, rule.name, condition, rule.action, rule.duration
        )
    }

    fn diff_rule_files(
        previous: &BTreeMap<String, Option<SystemTime>>,
        current: &BTreeMap<String, Option<SystemTime>>,
    ) -> Vec<String> {
        let mut changed = Vec::new();
        for (name, mtime) in previous {
            match current.get(name) {
                None => changed.push(name.clone()),
                Some(cur) if cur != mtime => changed.push(name.clone()),
                _ => {}
            }
        }
        for name in current.keys() {
            if !previous.contains_key(name) {
                changed.push(name.clone());
            }
        }
        changed.sort();
        changed.dedup();
        changed
    }

    fn removed_rule_files(
        previous: &BTreeMap<String, Option<SystemTime>>,
        current: &BTreeMap<String, Option<SystemTime>>,
    ) -> Vec<String> {
        previous
            .keys()
            .filter(|name| !current.contains_key(*name))
            .cloned()
            .collect()
    }

    fn setup_fs_trigger(
        paths: &[PathBuf],
    ) -> (
        Option<InotifyTrigger>,
        bool,
        tokio::sync::mpsc::UnboundedReceiver<()>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let fd = {
            // IN_NONBLOCK keeps shutdown responsive; CLOEXEC avoids fd leaks across exec.
            let flags = nix::libc::IN_NONBLOCK | nix::libc::IN_CLOEXEC;
            // SAFETY: Calling libc syscall with constant flags and checking return value.
            let created = unsafe { nix::libc::inotify_init1(flags) };
            if created < 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!("failed to initialize inotify, using poll-only fallback: {err}");
                return (None, false, rx);
            }
            created
        };

        let mut watched_any = false;
        let mask = nix::libc::IN_CREATE
            | nix::libc::IN_MODIFY
            | nix::libc::IN_DELETE
            | nix::libc::IN_MOVED_FROM
            | nix::libc::IN_MOVED_TO
            | nix::libc::IN_CLOSE_WRITE
            | nix::libc::IN_DELETE_SELF
            | nix::libc::IN_MOVE_SELF;

        for path in paths {
            let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(path = %path.display(), "failed to watch path with interior NUL, keeping poll fallback");
                    continue;
                }
            };

            // SAFETY: fd is valid from inotify_init1; c_path is a valid C string.
            let watch_rc = unsafe { nix::libc::inotify_add_watch(fd, c_path.as_ptr(), mask) };
            if watch_rc >= 0 {
                watched_any = true;
            } else {
                let err = std::io::Error::last_os_error();
                tracing::warn!(path = %path.display(), "failed to watch filesystem path, keeping poll fallback: {err}");
            }
        }

        if !watched_any {
            // SAFETY: fd was created by inotify_init1 and is no longer needed.
            unsafe {
                nix::libc::close(fd);
            }
            tracing::warn!("no filesystem watch targets registered, using poll-only fallback");
            return (None, false, rx);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];

            while !stop_thread.load(Ordering::Relaxed) {
                // SAFETY: fd is a live inotify descriptor; buffer is writable and sized correctly.
                let bytes_read = unsafe {
                    nix::libc::read(
                        fd,
                        buffer.as_mut_ptr().cast::<nix::libc::c_void>(),
                        buffer.len(),
                    )
                };

                if bytes_read < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        tracing::warn!("inotify read failed, keeping poll fallback active: {err}");
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }

                if bytes_read == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }

                let mut offset = 0_usize;
                let mut emit = false;
                while offset + std::mem::size_of::<nix::libc::inotify_event>()
                    <= bytes_read as usize
                {
                    // SAFETY: offset bounds are checked above for inotify_event header size.
                    let event = unsafe {
                        std::ptr::read_unaligned(
                            buffer[offset..].as_ptr().cast::<nix::libc::inotify_event>(),
                        )
                    };
                    if WatchService::should_forward_inotify_mask(event.mask) {
                        emit = true;
                    }

                    let event_size =
                        std::mem::size_of::<nix::libc::inotify_event>() + event.len as usize;
                    if event_size == 0 {
                        break;
                    }
                    offset = offset.saturating_add(event_size);
                }

                if emit {
                    let _ = tx.send(());
                }
            }

            // SAFETY: fd was created in this function and should be closed once worker exits.
            unsafe {
                nix::libc::close(fd);
            }
        });

        (
            Some(InotifyTrigger {
                stop,
                worker: Some(worker),
            }),
            true,
            rx,
        )
    }

    async fn read_rules_dir_file_state_async(
        path: &std::path::Path,
    ) -> Option<BTreeMap<String, Option<SystemTime>>> {
        let mut state = BTreeMap::new();
        let mut list_dirs = BTreeSet::new();
        let mut entries = tokio::fs::read_dir(path).await.ok()?;

        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_path = entry.path();
            if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let name = file_path.file_name()?.to_string_lossy().to_string();
            let modified = entry
                .metadata()
                .await
                .ok()
                .and_then(|meta| meta.modified().ok());
            state.insert(name, modified);

            let Ok(raw_rule) = tokio::fs::read_to_string(&file_path).await else {
                continue;
            };
            let Ok(rule_file) = serde_json::from_str::<RuleFile>(&raw_rule) else {
                continue;
            };

            if !rule_file.enabled {
                continue;
            }

            Self::collect_rule_list_dirs(&rule_file.operator, &mut list_dirs);
        }

        for list_dir in list_dirs {
            let dir_key = format!("listdir:{}", list_dir.display());
            let dir_modified = tokio::fs::metadata(&list_dir)
                .await
                .ok()
                .and_then(|meta| meta.modified().ok());
            state.insert(dir_key, dir_modified);

            let Ok(mut list_entries) = tokio::fs::read_dir(&list_dir).await else {
                continue;
            };

            while let Ok(Some(list_entry)) = list_entries.next_entry().await {
                let list_path = list_entry.path();
                let Some(file_name) = list_path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if file_name.starts_with('.') {
                    continue;
                }

                let Ok(metadata) = list_entry.metadata().await else {
                    continue;
                };
                if !metadata.is_file() {
                    continue;
                }

                let key = format!("list:{}:{}", list_dir.display(), file_name);
                let modified = metadata.modified().ok();
                state.insert(key, modified);
            }
        }

        Some(state)
    }

    fn collect_rule_list_dirs(operator: &RuleFileOperator, list_dirs: &mut BTreeSet<PathBuf>) {
        if operator.r#type.eq_ignore_ascii_case("lists") || operator.operand.starts_with("lists.") {
            let path = PathBuf::from(operator.data.as_str());
            if !path.as_os_str().is_empty() {
                list_dirs.insert(path);
            }
        }

        for child in &operator.list {
            Self::collect_rule_list_dirs(child, list_dirs);
        }
    }

    fn is_newer_mtime(current: Option<SystemTime>, previous: Option<SystemTime>) -> bool {
        matches!((previous, current), (Some(prev), Some(cur)) if cur > prev)
    }

    #[cfg(test)]
    pub(crate) fn probe_is_newer_mtime(
        current: Option<SystemTime>,
        previous: Option<SystemTime>,
    ) -> bool {
        Self::is_newer_mtime(current, previous)
    }
}

struct InotifyTrigger {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for InotifyTrigger {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl WatchService {
    pub(crate) fn spawn_config_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let config = self.config.clone();
        let rules = self.rules.clone();
        let firewall = self.firewall.clone();
        let stats = self.stats.clone();
        let alert_tx = self.alert_tx.clone();
        let reconfigure_proc_workers = self.reconfigure_proc_workers.clone();

        tokio::spawn(async move {
            let mut last_mtime: Option<SystemTime> = None;
            let initial_snapshot = config.snapshot_arc();
            let config_path = initial_snapshot.config_path.as_path();
            let targets = WatchService::watch_targets(config_path);
            let (_watcher, mut fs_rx_enabled, mut fs_rx) = WatchService::setup_fs_trigger(&targets);

            loop {
                let mut should_check = false;
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                        should_check = true;
                    }
                    event = fs_rx.recv(), if fs_rx_enabled => {
                        match event {
                            Some(()) => should_check = true,
                            None => {
                                fs_rx_enabled = false;
                                tracing::warn!("filesystem watch channel closed, continuing with poll-only fallback");
                            }
                        }
                    }
                }

                if !should_check {
                    continue;
                }

                let mtime = tokio::fs::metadata(config_path)
                    .await
                    .ok()
                    .and_then(|meta| meta.modified().ok());

                if WatchService::is_newer_mtime(mtime, last_mtime) {
                    tracing::debug!(path = %config_path.display(), "config file change detected, reloading runtime config");
                    let snapshot = config.snapshot_arc();
                    match config.reload().await {
                        Ok(updated) => {
                            let reload_proc = snapshot.proc_monitor_method
                                != updated.proc_monitor_method
                                || snapshot.audit_socket_path != updated.audit_socket_path;
                            let reload_fw = snapshot.firewall_backend.as_str()
                                != updated.firewall_backend.as_str()
                                || snapshot.firewall_config_path != updated.firewall_config_path
                                || snapshot.firewall_queue_num != updated.firewall_queue_num
                                || snapshot.firewall_queue_bypass != updated.firewall_queue_bypass;

                            crate::utils::config_reload::log_config_delta(
                                &snapshot, &updated, true,
                            );
                            tracing::debug!(
                                addr = %updated.client_addr,
                                log_level = updated.log_level,
                                ?updated.default_action,
                                ?updated.proc_monitor_method,
                                ?updated.firewall_backend,
                                "applying watched config update"
                            );
                            crate::ffi::nfqueue::NfqueueRuntimeState::set_default_action(
                                updated.default_action,
                            );
                            stats.apply_config(updated.stats);
                            crate::utils::config_reload::apply_gc_percent(updated.gc_percent);
                            tracing::info!(
                                "Stats, max events: {}, max stats: {}, max workers: {}",
                                updated.stats.max_stats,
                                updated.stats.max_events,
                                updated.stats.workers
                            );
                            for worker in 0..updated.stats.workers {
                                tracing::debug!("Stats worker #{} started.", worker);
                            }
                            tracing::info!(
                                max_events = updated.stats.max_events,
                                max_stats = updated.stats.max_stats,
                                workers = updated.stats.workers,
                                "stats settings reloaded"
                            );
                            if let Err(err) = crate::logging::LoggingState::apply_config(&updated) {
                                tracing::error!(
                                    "failed to apply runtime logging config after config file change: {err}"
                                );
                                enqueue_alert(
                                    &alert_tx,
                                    UiAlert::warning(format!(
                                        "failed to apply runtime logging config after config file change: {err}"
                                    )),
                                );
                            }
                            tracing::info!(
                                "rules.Loader.Reload(): {}",
                                updated.rules_path.display()
                            );
                            tracing::debug!(
                                "rules.Loader.Load(): {}",
                                updated.rules_path.display()
                            );
                            if let Err(err) = rules.load_path(&updated.rules_path).await {
                                tracing::error!(
                                    "failed to reload rules after config file change: {err}"
                                );
                                enqueue_alert(
                                    &alert_tx,
                                    UiAlert::warning(format!(
                                        "failed to reload rules after config file change: {err}"
                                    )),
                                );
                            } else {
                                tracing::info!(path = %updated.rules_path.display(), "rules path reloaded");
                            }
                            if let Err(err) = firewall.reconcile_from_config(&updated).await {
                                tracing::error!(
                                    "failed to reconcile firewall after config file change: {err}"
                                );
                                enqueue_alert(
                                    &alert_tx,
                                    UiAlert::warning(format!(
                                        "failed to reconcile firewall after config file change: {err}"
                                    )),
                                );
                            } else {
                                tracing::info!(backend = ?updated.firewall_backend, "firewall backend reconciled after config reload");
                            }
                            tracing::debug!("monitor.End()");
                            tracing::info!(
                                "Process monitor method {}",
                                WatchService::proc_monitor_label(snapshot.proc_monitor_method)
                            );
                            if let Err(err) =
                                reconfigure_proc_workers(Some(updated.proc_monitor_method)).await
                            {
                                tracing::error!(
                                    "failed to reconfigure process monitor workers after config reload: {err}"
                                );
                                enqueue_alert(
                                    &alert_tx,
                                    UiAlert::warning(format!(
                                        "failed to reconfigure process monitor workers after config reload: {err}"
                                    )),
                                );
                            } else {
                                tracing::info!(?updated.proc_monitor_method, "process monitor workers reconfigured after config reload");
                            }

                            if (reload_proc || reload_fw) && updated.flush_conns_on_start {
                                crate::utils::config_reload::flush_established_connections().await;
                            } else {
                                tracing::debug!("[config] not flushing established connections");
                            }
                        }
                        Err(err) => {
                            tracing::error!("failed to reload config from watched file: {err}");
                            enqueue_alert(
                                &alert_tx,
                                UiAlert::warning(format!(
                                    "failed to reload config from watched file: {err}"
                                )),
                            );
                        }
                    }
                }

                if mtime.is_some() {
                    last_mtime = mtime;
                }
            }
        })
    }

    pub(crate) fn spawn_rules_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let rules = self.rules.clone();

        tokio::spawn(async move {
            let rules_path = rules.rules_path_arc().await;
            let targets = WatchService::watch_targets(rules_path.as_path());
            let (_watcher, mut fs_rx_enabled, mut fs_rx) = WatchService::setup_fs_trigger(&targets);
            let mut last_state =
                WatchService::read_rules_dir_file_state_async(rules_path.as_path()).await;

            loop {
                let mut should_check = false;
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                        should_check = true;
                    }
                    event = fs_rx.recv(), if fs_rx_enabled => {
                        match event {
                            Some(()) => should_check = true,
                            None => {
                                fs_rx_enabled = false;
                                tracing::warn!("filesystem watch channel closed, continuing with poll-only fallback");
                            }
                        }
                    }
                }

                if !should_check {
                    continue;
                }

                let path = rules.rules_path_arc().await;
                let state = WatchService::read_rules_dir_file_state_async(path.as_path()).await;

                let changed = match (&last_state, &state) {
                    (Some(prev), Some(cur)) => prev != cur,
                    (None, Some(_)) => false,
                    (Some(_), None) => true,
                    (None, None) => false,
                };

                if changed {
                    let previous_default = BTreeMap::new();
                    let current_default = BTreeMap::new();
                    let previous_files = last_state.as_ref().unwrap_or(&previous_default);
                    let current_files = state.as_ref().unwrap_or(&current_default);
                    for file_name in WatchService::diff_rule_files(&previous_files, &current_files)
                    {
                        tracing::info!("Ruleset changed due to {}, reloading ...", file_name);
                    }
                    let previous_rules = rules.list_proto_arc().await;
                    if let Err(err) = rules.reload().await {
                        tracing::error!(path = %path.display(), "failed to reload rules after directory change: {err}");
                    } else {
                        for file_name in
                            WatchService::removed_rule_files(&previous_files, &current_files)
                        {
                            if let Some(stem) = std::path::Path::new(&file_name)
                                .file_stem()
                                .and_then(|stem| stem.to_str())
                                && let Some(rule) =
                                    previous_rules.iter().find(|rule| rule.name == stem)
                            {
                                tracing::info!("{}", WatchService::format_deleted_rule(rule));
                            }
                            tracing::info!("Rule deleted {}", file_name);
                        }
                        tracing::info!(path = %path.display(), "rules reloaded after directory change");
                    }
                }

                last_state = state;
            }
        })
    }

    pub(crate) fn spawn_tasks_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let config = self.config.clone();
        let process = self.process.clone();
        let task_reply_tx = self.task_reply_tx.clone();
        let alert_tx = self.alert_tx.clone();
        let task_runtime_service = task_runtime::TaskRuntimeService;

        tokio::spawn(async move {
            let mut task_handles: std::collections::HashMap<String, task_runtime::DiskTaskRuntime> =
                std::collections::HashMap::new();
            let initial_snapshot = config.snapshot_arc();
            let tasks_config_path = initial_snapshot.tasks_config_path.as_path();
            let mut targets = WatchService::watch_targets(tasks_config_path);
            if let Some(parent) = tasks_config_path.parent() {
                targets.push(parent.to_path_buf());
            }
            targets.sort();
            targets.dedup();
            let (_watcher, mut fs_rx_enabled, mut fs_rx) = WatchService::setup_fs_trigger(&targets);

            loop {
                let mut should_sync = false;
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                        should_sync = true;
                    }
                    event = fs_rx.recv(), if fs_rx_enabled => {
                        match event {
                            Some(()) => should_sync = true,
                            None => {
                                fs_rx_enabled = false;
                                tracing::warn!("filesystem watch channel closed, continuing with poll-only fallback");
                            }
                        }
                    }
                }

                if !should_sync {
                    continue;
                }

                if let Err(err) = task_runtime_service
                    .sync_disk_tasks(
                        tasks_config_path,
                        &mut task_handles,
                        process.clone(),
                        task_reply_tx.clone(),
                    )
                    .await
                {
                    tracing::error!(path = %tasks_config_path.display(), "failed to sync disk tasks: {err}");
                    enqueue_alert(
                        &alert_tx,
                        UiAlert::warning(format!("failed to sync disk tasks: {err}")),
                    );
                }
            }

            task_runtime_service.stop_disk_tasks(&mut task_handles);
        })
    }

    pub(crate) fn spawn_firewall_watch_task(&self) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let config = self.config.clone();
        let firewall = self.firewall.clone();

        tokio::spawn(async move {
            loop {
                let snapshot = config.snapshot_arc();
                let interval = snapshot.firewall_monitor_interval.as_str();
                let interval = WatchService::parse_firewall_monitor_interval(interval);
                let sleep_for = if interval.is_zero() {
                    std::time::Duration::from_secs(1)
                } else {
                    interval
                };

                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(sleep_for) => {}
                }

                if interval.is_zero() {
                    continue;
                }

                if let Err(err) = firewall.heal_if_drifted().await {
                    tracing::warn!("failed to heal firewall drift: {err}");
                }
            }
        })
    }
}

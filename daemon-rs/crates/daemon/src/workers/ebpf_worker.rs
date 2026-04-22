use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    process::Command,
    sync::Mutex,
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[cfg(feature = "native-ebpf-ringbuf")]
use std::sync::Arc;

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::{
    bus::Bus,
    models::ebpf_runtime::{BpfMap, BpfProgram},
    models::kernel_event::KernelEvent,
    services::ebpf_runtime_service::EbpfRuntimeService,
    tunables::RuntimeTunables,
    workers::control::{
        OneShotWorker, WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus,
        WorkerState,
    },
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

struct EbpfWorkerRuntime {
    shutdown: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

pub struct EbpfWorkerControl {
    bus: Bus,
    daemon_shutdown: CancellationToken,
    prune_policy: EbpfMapPrunePolicy,
    runtime: Mutex<EbpfWorkerRuntime>,
}

impl EbpfWorkerControl {
    pub fn new(bus: Bus, daemon_shutdown: CancellationToken, tunables: RuntimeTunables) -> Self {
        let worker_shutdown = daemon_shutdown.child_token();
        let prune_policy = EbpfMapPrunePolicy::from_tunables(tunables);
        let handle = Self::spawn_worker_thread(bus.clone(), worker_shutdown.clone(), prune_policy);
        Self {
            bus,
            daemon_shutdown,
            prune_policy,
            runtime: Mutex::new(EbpfWorkerRuntime {
                shutdown: worker_shutdown,
                handle: Some(handle),
            }),
        }
    }

    fn stop_worker(&self) -> WorkerCommandResult {
        if let Ok(runtime) = self.runtime.lock() {
            runtime.shutdown.cancel();
            WorkerCommandResult::Applied
        } else {
            WorkerCommandResult::Unsupported
        }
    }

    fn start_worker(&self) -> WorkerCommandResult {
        if self.daemon_shutdown.is_cancelled() {
            return WorkerCommandResult::Unsupported;
        }

        let Ok(mut runtime) = self.runtime.lock() else {
            return WorkerCommandResult::Unsupported;
        };

        let needs_start = runtime
            .handle
            .as_ref()
            .is_none_or(|handle| handle.is_finished());

        if needs_start {
            if let Some(handle) = runtime.handle.take() {
                let _ = handle.join();
            }

            runtime.shutdown = self.daemon_shutdown.child_token();
            runtime.handle = Some(Self::spawn_worker_thread(
                self.bus.clone(),
                runtime.shutdown.clone(),
                self.prune_policy,
            ));
        }

        WorkerCommandResult::Applied
    }

    fn spawn_worker_thread(
        bus: Bus,
        shutdown: CancellationToken,
        prune_policy: EbpfMapPrunePolicy,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let runtime = match EbpfRuntimeService::load_existing_objects() {
                Ok(runtime) => {
                    debug!(
                        process_obj = ?runtime.process_obj,
                        dns_obj = ?runtime.dns_obj,
                        "eBPF object discovery initialized"
                    );
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcessMapHit {
                            pid: std::process::id(),
                            uid: 0,
                            note: "eBPF object discovery active".into(),
                        },
                    );
                    Some(runtime)
                }
                Err(err) => {
                    warn!("eBPF runtime not available: {err}");
                    None
                }
            };

            let mut state = SupervisorState::default();
            let mut native_ringbuf = NativeRingbuf::try_open().ok();
            if native_ringbuf.is_some() {
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::EbpfProcessMapHit {
                        pid: std::process::id(),
                        uid: 0,
                        note: "native eBPF ringbuf consumer enabled".into(),
                    },
                );
            }

            if let Some(runtime) = runtime.as_ref() {
                Self::ensure_ebpf_runtime_loaded(runtime, &bus);
            }

            Self::supervise_runtime(&bus, &mut state, prune_policy);

            let mut last_reconcile = Instant::now();

            while !shutdown.is_cancelled() {
                if let Some(consumer) = native_ringbuf.as_mut()
                    && let Err(err) = consumer.poll_and_emit(&bus)
                {
                    warn!("native eBPF ringbuf poll failed, disabling consumer: {err}");
                    native_ringbuf = None;
                }

                if last_reconcile.elapsed() >= Duration::from_secs(30) {
                    if let Some(runtime) = runtime.as_ref() {
                        Self::ensure_ebpf_runtime_loaded(runtime, &bus);
                    }
                    last_reconcile = Instant::now();
                }

                Self::supervise_runtime(&bus, &mut state, prune_policy);
                if crate::workers::sleep_with_shutdown(
                    &shutdown,
                    Duration::from_secs(5),
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn probe_extract_pid_uid(entry: &Value) -> Option<(u32, u32)> {
        Self::extract_pid_uid(entry)
    }

    #[cfg(test)]
    pub(crate) fn probe_find_numeric(node: &Value, wanted_keys: &[&str]) -> Option<u64> {
        Self::find_numeric(node, wanted_keys)
    }
}

impl WorkerControl for EbpfWorkerControl {
    fn worker_name(&self) -> &'static str {
        "ebpf"
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Stop => self.stop_worker(),
            WorkerCommand::Start => self.start_worker(),
            WorkerCommand::Probe => WorkerCommandResult::Applied,
        }
    }

    fn state(&self) -> WorkerState {
        let Ok(runtime) = self.runtime.lock() else {
            return WorkerState::Unknown;
        };

        if runtime.shutdown.is_cancelled() {
            WorkerState::Stopped
        } else if runtime
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
        {
            WorkerState::Running
        } else {
            WorkerState::Stopped
        }
    }

    fn is_finished(&self) -> bool {
        let Ok(runtime) = self.runtime.lock() else {
            return true;
        };

        runtime
            .handle
            .as_ref()
            .is_none_or(|handle| handle.is_finished())
    }

    fn join(self: Box<Self>) -> WorkerJoinStatus {
        self.stop();

        let handle = self
            .runtime
            .lock()
            .ok()
            .and_then(|mut runtime| runtime.handle.take());

        match handle {
            Some(handle) => match handle.join() {
                Ok(()) => WorkerJoinStatus::Stopped,
                Err(_) => WorkerJoinStatus::Panicked,
            },
            None => WorkerJoinStatus::Stopped,
        }
    }
}

impl OneShotWorker for EbpfWorkerControl {}

impl EbpfWorkerControl {
    fn ensure_ebpf_runtime_loaded(runtime: &EbpfRuntimeService, bus: &Bus) {
        let Some(bpftool) = Self::command_path("bpftool") else {
            return;
        };

        let mut loaded_any = false;

        let has_process_events = Path::new("/sys/fs/bpf/opensnitch/events").exists()
            || Path::new("/sys/fs/bpf/opensnitch_procs/events").exists();
        let has_dns_events = Path::new("/sys/fs/bpf/opensnitch_dns/events").exists();

        if let Some(obj) = runtime.process_obj.as_ref()
            && !has_process_events
            && Self::try_load_object_with_bpftool(&bpftool, obj, "/sys/fs/bpf/opensnitch")
        {
            loaded_any = true;
        }

        if let Some(obj) = runtime.dns_obj.as_ref()
            && !has_dns_events
            && Self::try_load_object_with_bpftool(&bpftool, obj, "/sys/fs/bpf/opensnitch_dns")
        {
            loaded_any = true;
        }

        if loaded_any {
            let _ = crate::workers::dispatch_kernel_event_with_backoff(
                &bus.kernel_tx,
                KernelEvent::EbpfProcessMapHit {
                    pid: std::process::id(),
                    uid: 0,
                    note:
                        "eBPF runtime attempted object load/attach for missing opensnitch programs"
                            .to_string(),
                },
            );
        }
    }

    fn try_load_object_with_bpftool(bpftool: &str, obj: &std::path::Path, pin_root: &str) -> bool {
        let obj = obj.to_string_lossy();
        let _ = fs::create_dir_all(pin_root);

        let attempts: &[&[&str]] = &[
            &["prog", "loadall", &obj, pin_root, "autoattach"],
            &["prog", "loadall", &obj, pin_root],
        ];

        for args in attempts {
            let output = Command::new(bpftool).args(*args).output();
            let Ok(output) = output else {
                continue;
            };

            if output.status.success() || Self::is_already_pinned_error(&output.stderr) {
                return true;
            }
        }

        false
    }

    fn is_already_pinned_error(stderr: &[u8]) -> bool {
        let stderr = String::from_utf8_lossy(stderr);
        stderr.contains("failed to pin at") && stderr.contains("-EEXIST")
    }
}

#[derive(Debug, Default)]
struct SupervisorState {
    seen_hits: HashMap<(u32, u32, u32), Instant>,
    pressure_maps: HashSet<u32>,
}

#[derive(Debug, Clone, Copy)]
struct EbpfMapPrunePolicy {
    enabled: bool,
    threshold_percent: usize,
    target_percent: usize,
}

impl EbpfMapPrunePolicy {
    fn from_tunables(t: RuntimeTunables) -> Self {
        Self {
            enabled: t.ebpf_map_prune_enabled,
            threshold_percent: t.ebpf_map_prune_threshold_percent,
            target_percent: t.ebpf_map_prune_target_percent,
        }
    }
}

impl EbpfWorkerControl {
    fn supervise_runtime(bus: &Bus, state: &mut SupervisorState, prune_policy: EbpfMapPrunePolicy) {
        Self::prune_seen_hits(state);

        let Some(bpftool) = Self::command_path("bpftool") else {
            return;
        };

        let programs = Self::list_programs(&bpftool);
        let maps = Self::list_maps(&bpftool);

        if programs.is_empty() || maps.is_empty() {
            return;
        }

        let opensnitch_programs: Vec<&BpfProgram> = programs
            .iter()
            .filter(|p| p.name.to_ascii_lowercase().contains("opensnitch"))
            .collect();

        if opensnitch_programs.is_empty() {
            return;
        }

        let map_ids: HashSet<u32> = opensnitch_programs
            .iter()
            .flat_map(|p| p.map_ids.iter().copied())
            .collect();

        if map_ids.is_empty() {
            return;
        }

        let mut map_by_id: HashMap<u32, BpfMap> = HashMap::new();
        for map in maps {
            map_by_id.insert(map.id, map);
        }

        for map_id in map_ids {
            let Some(map_meta) = map_by_id.get(&map_id) else {
                continue;
            };

            let entries = Self::dump_map(&bpftool, map_id);
            let entry_count = entries.len() as u32;
            Self::maybe_emit_pressure(bus, state, map_meta, entry_count);
            let pruned = Self::prune_map_entries(
                &bpftool,
                map_id,
                map_meta,
                &entries,
                entry_count,
                prune_policy,
            );
            if pruned > 0 {
                let note = format!(
                    "eBPF map '{}' (id={map_id}) pruned {pruned} entries under pressure",
                    map_meta.name
                );
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::EbpfProcessMapHit {
                        pid: std::process::id(),
                        uid: 0,
                        note,
                    },
                );
            }

            for entry in entries {
                if let Some((pid, uid)) = Self::extract_pid_uid(&entry) {
                    let key = (map_id, pid, uid);
                    let should_emit = state
                        .seen_hits
                        .get(&key)
                        .map(|seen_at| seen_at.elapsed() >= Duration::from_secs(30))
                        .unwrap_or(true);

                    if should_emit {
                        state.seen_hits.insert(key, Instant::now());
                        let _ = crate::workers::dispatch_kernel_event_with_backoff(
                            &bus.kernel_tx,
                            KernelEvent::EbpfProcessMapHit {
                                pid,
                                uid,
                                note: format!(
                                    "eBPF map '{}' (id={map_id}) lookup hit",
                                    map_meta.name
                                ),
                            },
                        );
                    }
                }
            }
        }

        let opensnitch_prog_count = opensnitch_programs.len();
        let _ = crate::workers::dispatch_kernel_event_with_backoff(
            &bus.kernel_tx,
            KernelEvent::EbpfProcessMapHit {
                pid: std::process::id(),
                uid: 0,
                note: format!(
                    "bpftool supervisor active: {opensnitch_prog_count} opensnitch programs monitored"
                ),
            },
        );
    }

    fn prune_map_entries(
        bpftool: &str,
        map_id: u32,
        map_meta: &BpfMap,
        entries: &[Value],
        entry_count: u32,
        policy: EbpfMapPrunePolicy,
    ) -> usize {
        if !policy.enabled || map_meta.max_entries == 0 {
            return 0;
        }

        let threshold_count =
            ((map_meta.max_entries as usize * policy.threshold_percent) + 99) / 100;
        if entry_count as usize <= threshold_count {
            return 0;
        }

        let target_count = (map_meta.max_entries as usize * policy.target_percent) / 100;
        if entry_count as usize <= target_count {
            return 0;
        }

        let delete_budget = (entry_count as usize).saturating_sub(target_count);
        if delete_budget == 0 {
            return 0;
        }

        let mut deleted = 0;
        for entry in entries.iter().take(delete_budget) {
            let Some(key_bytes) = Self::extract_key_bytes(entry) else {
                continue;
            };
            if Self::delete_map_key(bpftool, map_id, &key_bytes) {
                deleted += 1;
            }
        }

        if deleted > 0 {
            debug!(
                map_id,
                map = %map_meta.name,
                deleted,
                entry_count,
                max_entries = map_meta.max_entries,
                threshold_percent = policy.threshold_percent,
                target_percent = policy.target_percent,
                "eBPF map prune applied"
            );
        }

        deleted
    }

    fn delete_map_key(bpftool: &str, map_id: u32, key_bytes: &[u8]) -> bool {
        let mut args = vec![
            "map".to_string(),
            "delete".to_string(),
            "id".to_string(),
            map_id.to_string(),
            "key".to_string(),
            "hex".to_string(),
        ];
        for b in key_bytes {
            args.push(format!("{b:02x}"));
        }

        let Ok(output) = Command::new(bpftool).args(&args).output() else {
            return false;
        };
        output.status.success()
    }

    fn extract_key_bytes(entry: &Value) -> Option<Vec<u8>> {
        let key = entry.get("key")?;
        let mut out = Vec::new();
        Self::collect_u8_values(key, &mut out);
        if out.is_empty() { None } else { Some(out) }
    }

    fn collect_u8_values(node: &Value, out: &mut Vec<u8>) {
        match node {
            Value::Number(n) => {
                if let Some(v) = n.as_u64().and_then(|v| u8::try_from(v).ok()) {
                    out.push(v);
                }
            }
            Value::Array(values) => {
                for value in values {
                    Self::collect_u8_values(value, out);
                }
            }
            Value::Object(map) => {
                for value in map.values() {
                    Self::collect_u8_values(value, out);
                }
            }
            Value::String(s) => {
                if let Ok(v) = u8::from_str_radix(s.trim_start_matches("0x"), 16) {
                    out.push(v);
                }
            }
            _ => {}
        }
    }

    fn command_path(bin: &str) -> Option<String> {
        let paths = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
        None
    }

    fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(bin).args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    }

    fn run_json_capture(bin: &str, args: &[&str]) -> Option<Value> {
        let mut argv = vec!["-j"];
        argv.extend_from_slice(args);

        let out = Self::run_capture(bin, &argv)?;
        serde_json::from_str(&out).ok()
    }

    fn list_programs(bpftool: &str) -> Vec<BpfProgram> {
        Self::run_json_capture(bpftool, &["prog", "show"])
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default()
    }

    fn list_maps(bpftool: &str) -> Vec<BpfMap> {
        Self::run_json_capture(bpftool, &["map", "show"])
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default()
    }

    fn dump_map(bpftool: &str, map_id: u32) -> Vec<Value> {
        Self::run_json_capture(bpftool, &["map", "dump", "id", &map_id.to_string()])
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default()
    }

    fn maybe_emit_pressure(bus: &Bus, state: &mut SupervisorState, map: &BpfMap, entries: u32) {
        if map.max_entries == 0 {
            return;
        }

        let ratio = entries as f64 / map.max_entries as f64;
        if ratio >= 0.8 {
            if state.pressure_maps.insert(map.id) {
                let note = format!(
                    "eBPF map pressure: map '{}' (id={}) at {}/{} entries",
                    map.name, map.id, entries, map.max_entries
                );
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::EbpfProcessMapHit {
                        pid: std::process::id(),
                        uid: 0,
                        note,
                    },
                );
            }
        } else {
            state.pressure_maps.remove(&map.id);
        }
    }

    fn extract_pid_uid(entry: &Value) -> Option<(u32, u32)> {
        let value = entry.get("value").unwrap_or(entry);
        let pid = Self::find_numeric(value, &["pid", "tgid"])? as u32;

        let uid = Self::find_numeric(value, &["uid"])
            .map(|v| v as u32)
            .or_else(|| {
                Self::find_numeric(value, &["uid_gid"]).map(|v| {
                    let lo = v & 0xFFFF_FFFF;
                    lo as u32
                })
            })
            .unwrap_or(0);

        Some((pid, uid))
    }

    fn find_numeric(node: &Value, wanted_keys: &[&str]) -> Option<u64> {
        match node {
            Value::Number(_) => None,
            Value::Object(map) => {
                for (k, v) in map {
                    let key = k.to_ascii_lowercase();
                    if wanted_keys.iter().any(|w| key == *w) {
                        if let Some(num) = v.as_u64() {
                            return Some(num);
                        }

                        if let Some(num) = Self::find_first_number(v) {
                            return Some(num);
                        }
                    }
                }

                for value in map.values() {
                    if let Some(num) = Self::find_numeric(value, wanted_keys) {
                        return Some(num);
                    }
                }

                None
            }
            Value::Array(items) => items
                .iter()
                .find_map(|item| Self::find_numeric(item, wanted_keys)),
            _ => None,
        }
    }

    fn find_first_number(node: &Value) -> Option<u64> {
        match node {
            Value::Number(n) => n.as_u64(),
            Value::Object(map) => map.values().find_map(Self::find_first_number),
            Value::Array(items) => items.iter().find_map(Self::find_first_number),
            _ => None,
        }
    }

    fn prune_seen_hits(state: &mut SupervisorState) {
        let ttl = Duration::from_secs(5 * 60);
        state.seen_hits.retain(|_, seen_at| seen_at.elapsed() < ttl);
        trace!(seen_hits = state.seen_hits.len(), "pruned eBPF hit cache");
    }
}

#[cfg(feature = "native-ebpf-ringbuf")]
struct NativeRingbuf {
    _map: &'static mut libbpf_rs::MapHandle,
    ringbuf: libbpf_rs::RingBuffer<'static>,
    queue: Arc<Mutex<Vec<NativeQueuedEvent>>>,
}

#[cfg(feature = "native-ebpf-ringbuf")]
const EV_TYPE_EXEC: u64 = 1;
#[cfg(feature = "native-ebpf-ringbuf")]
const EV_TYPE_EXECVEAT: u64 = 2;
#[cfg(feature = "native-ebpf-ringbuf")]
const EV_TYPE_FORK: u64 = 3;
#[cfg(feature = "native-ebpf-ringbuf")]
const EV_TYPE_SCHED_EXIT: u64 = 4;

#[cfg(feature = "native-ebpf-ringbuf")]
const EXEC_HDR_LEN: usize = 26;
#[cfg(feature = "native-ebpf-ringbuf")]
const MAX_PATH_LEN: usize = 4096;
#[cfg(feature = "native-ebpf-ringbuf")]
const MAX_ARGS: usize = 20;
#[cfg(feature = "native-ebpf-ringbuf")]
const MAX_ARG_LEN: usize = 256;
#[cfg(feature = "native-ebpf-ringbuf")]
const TASK_COMM_LEN: usize = 16;
#[cfg(feature = "native-ebpf-ringbuf")]
const EXEC_EVENT_LEN: usize =
    EXEC_HDR_LEN + MAX_PATH_LEN + (MAX_ARGS * MAX_ARG_LEN) + TASK_COMM_LEN;

#[cfg(feature = "native-ebpf-ringbuf")]
enum NativeQueuedEvent {
    MapHit { pid: u32, uid: u32, note: String },
    DnsResolved { ip: String, host: String },
}

impl EbpfWorkerControl {
    #[cfg(feature = "native-ebpf-ringbuf")]
    fn parse_native_sample(sample: &[u8]) -> Option<NativeQueuedEvent> {
        if let Some((ip, host)) = Self::parse_dns_sample(sample) {
            return Some(NativeQueuedEvent::DnsResolved { ip, host });
        }

        if sample.len() >= EXEC_EVENT_LEN {
            return Self::parse_exec_sample(sample);
        }

        if sample.len() >= 8 {
            let pid = u32::from_ne_bytes([sample[0], sample[1], sample[2], sample[3]]);
            let uid = u32::from_ne_bytes([sample[4], sample[5], sample[6], sample[7]]);
            return Some(NativeQueuedEvent::MapHit {
                pid,
                uid,
                note: format!("native ringbuf generic sample {} bytes", sample.len()),
            });
        }

        None
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    fn parse_exec_sample(sample: &[u8]) -> Option<NativeQueuedEvent> {
        let ev_type = Self::read_u64_ne_at(sample, 0)?;
        let pid = Self::read_u32_ne_at(sample, 8)?;
        let uid = Self::read_u32_ne_at(sample, 12)?;
        let ppid = Self::read_u32_ne_at(sample, 16)?;
        let ret_code = Self::read_u32_ne_at(sample, 20)?;
        let args_count = *sample.get(24)? as usize;
        let args_partial = *sample.get(25)?;

        let filename_off = EXEC_HDR_LEN;
        let args_off = filename_off + MAX_PATH_LEN;
        let comm_off = args_off + (MAX_ARGS * MAX_ARG_LEN);

        let filename = Self::read_c_string(sample.get(filename_off..filename_off + MAX_PATH_LEN)?);
        let comm = Self::read_c_string(sample.get(comm_off..comm_off + TASK_COMM_LEN)?);

        let mut args = Vec::new();
        let count = args_count.min(MAX_ARGS);
        for idx in 0..count {
            let start = args_off + (idx * MAX_ARG_LEN);
            let end = start + MAX_ARG_LEN;
            let arg = Self::read_c_string(sample.get(start..end)?);
            if !arg.is_empty() {
                args.push(arg);
            }
        }

        let event_name = match ev_type {
            EV_TYPE_EXEC => "exec",
            EV_TYPE_EXECVEAT => "execveat",
            EV_TYPE_FORK => "fork",
            EV_TYPE_SCHED_EXIT => "sched_exit",
            _ => "unknown",
        };

        let mut note = format!(
            "native ringbuf {event_name}: pid={pid} ppid={ppid} uid={uid} comm='{}' exe='{}' ret={ret_code}",
            comm, filename
        );
        if !args.is_empty() {
            note.push_str(&format!(" args='{}'", args.join(" ")));
        }
        if args_partial != 0 {
            note.push_str(" args_partial=1");
        }

        Some(NativeQueuedEvent::MapHit { pid, uid, note })
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    fn parse_dns_sample(sample: &[u8]) -> Option<(String, String)> {
        if sample.len() != DNS_EVENT_LEN {
            return None;
        }

        let addr_type = Self::read_u32_ne_at(sample, 0)?;
        if addr_type != 2 && addr_type != 10 {
            return None;
        }

        let ip_bytes = sample.get(4..20)?;
        let host_bytes = sample.get(20..272)?;
        let host = Self::read_c_string(host_bytes);
        if host.is_empty() {
            return None;
        }

        let ip = if addr_type == 2 {
            std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]).to_string()
        } else {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(ip_bytes);
            std::net::Ipv6Addr::from(octets).to_string()
        };

        Some((ip, host))
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    fn read_u64_ne_at(sample: &[u8], off: usize) -> Option<u64> {
        let s = sample.get(off..off + 8)?;
        Some(u64::from_ne_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    fn read_u32_ne_at(sample: &[u8], off: usize) -> Option<u32> {
        let s = sample.get(off..off + 4)?;
        Some(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    fn read_c_string(value: &[u8]) -> String {
        let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
        String::from_utf8_lossy(&value[..end]).to_string()
    }
}

#[cfg(feature = "native-ebpf-ringbuf")]
impl NativeRingbuf {
    fn try_open() -> Result<Self, String> {
        let candidates = [
            "/sys/fs/bpf/opensnitch/events",
            "/sys/fs/bpf/opensnitch_dns/events",
            "/sys/fs/bpf/opensnitch_procs/events",
        ];

        let map_path = candidates
            .iter()
            .find(|path| Path::new(path).exists())
            .ok_or_else(|| "no pinned opensnitch ringbuf map found".to_string())?;

        let map = libbpf_rs::MapHandle::from_pinned_path(map_path)
            .map_err(|err| format!("open pinned ringbuf map failed ({map_path}): {err}"))?;
        let map = Box::leak(Box::new(map));

        let queue = Arc::new(Mutex::new(Vec::with_capacity(64)));
        let queue_closure = Arc::clone(&queue);

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(map, move |sample: &[u8]| -> i32 {
                if let Some(parsed) = EbpfWorkerControl::parse_native_sample(sample) {
                    if let Ok(mut q) = queue_closure.lock() {
                        q.push(parsed);
                    }
                }
                0
            })
            .map_err(|err| format!("attach ringbuf callback failed: {err}"))?;

        let ringbuf = builder
            .build()
            .map_err(|err| format!("build ringbuf reader failed: {err}"))?;

        Ok(Self {
            _map: map,
            ringbuf,
            queue,
        })
    }

    fn poll_and_emit(&mut self, bus: &Bus) -> Result<(), String> {
        self.ringbuf
            .poll(Duration::from_millis(25))
            .map_err(|err| format!("ringbuf poll failed: {err}"))?;

        let mut queue = self
            .queue
            .lock()
            .map_err(|_| "ringbuf queue lock poisoned".to_string())?;

        for event in queue.drain(..) {
            match event {
                NativeQueuedEvent::MapHit { pid, uid, note } => {
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcessMapHit { pid, uid, note },
                    );
                }
                NativeQueuedEvent::DnsResolved { ip, host } => {
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::DnsResolved { ip, host },
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "native-ebpf-ringbuf")]
const DNS_EVENT_LEN: usize = 4 + 16 + 252;

#[cfg(not(feature = "native-ebpf-ringbuf"))]
struct NativeRingbuf;

#[cfg(not(feature = "native-ebpf-ringbuf"))]
impl NativeRingbuf {
    fn try_open() -> Result<Self, String> {
        Err("native-ebpf-ringbuf feature disabled".to_string())
    }

    fn poll_and_emit(&mut self, _bus: &Bus) -> Result<(), String> {
        Ok(())
    }
}

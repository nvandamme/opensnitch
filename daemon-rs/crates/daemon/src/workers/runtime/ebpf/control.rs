use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
    bus::Bus,
    models::dns_payload::DnsPayload,
    models::ebpf_payload::EbpfProcStatePayload,
    models::ebpf_state::{BpfMap, BpfProgram},
    models::kernel_event::KernelEvent,
    services::{
        connection::ConnectionService,
        dns::{DnsEbpfEventDeduper, DnsService},
        ebpf::{EbpfRingbufConsumer, EbpfService},
        process::ProcessService,
    },
    tunables::RuntimeTunables,
    utils::byte_read::read_ne_value_at,
    utils::command_path::resolve_command_path,
    utils::hex_parse::parse_hex_token,
    utils::path_text::lossy_os,
    workers::runtime::control::{
        WorkerCommandResult, impl_restartable_thread_worker_control,
    },
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CONN_SUPERVISE_INTERVAL: Duration = Duration::from_secs(5);
const EBPFRING_ACTIVE_LOOP_INTERVAL: Duration = Duration::from_millis(50);

struct EbpfWorkerRuntime {
    shutdown: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EbpfWorkerMode {
    enable_dns: bool,
    enable_proc: bool,
    enable_conn: bool,
}

impl EbpfWorkerMode {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: Self = Self {
        enable_dns: true,
        enable_proc: true,
        enable_conn: true,
    };

    pub(crate) const DNS_ONLY: Self = Self {
        enable_dns: true,
        enable_proc: false,
        enable_conn: false,
    };

    pub(crate) const PROC_ONLY: Self = Self {
        enable_dns: false,
        enable_proc: true,
        enable_conn: false,
    };

    pub(crate) const CONN_ONLY: Self = Self {
        enable_dns: false,
        enable_proc: false,
        enable_conn: true,
    };

    fn native_ringbuf_requested(&self) -> bool {
        self.enable_proc || self.enable_dns
    }
}

pub struct EbpfWorkerControl {
    bus: Bus,
    daemon_shutdown: CancellationToken,
    prune_policy: EbpfMapPrunePolicy,
    mode: EbpfWorkerMode,
    worker_name: &'static str,
    runtime: Mutex<EbpfWorkerRuntime>,
}

impl EbpfWorkerControl {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(bus: Bus, daemon_shutdown: CancellationToken, tunables: RuntimeTunables) -> Self {
        Self::new_with_mode(bus, daemon_shutdown, tunables, EbpfWorkerMode::ALL, "ebpf")
    }

    pub(crate) fn new_with_mode(
        bus: Bus,
        daemon_shutdown: CancellationToken,
        tunables: RuntimeTunables,
        mode: EbpfWorkerMode,
        worker_name: &'static str,
    ) -> Self {
        let worker_shutdown = daemon_shutdown.child_token();
        let prune_policy = EbpfMapPrunePolicy::from_tunables(tunables);
        let handle = Self::spawn_worker_thread(
            bus.clone(),
            worker_shutdown.clone(),
            prune_policy,
            mode,
            worker_name,
        );
        Self {
            bus,
            daemon_shutdown,
            prune_policy,
            mode,
            worker_name,
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
                self.mode,
                self.worker_name,
            ));
        }

        WorkerCommandResult::Applied
    }

    fn spawn_worker_thread(
        bus: Bus,
        shutdown: CancellationToken,
        prune_policy: EbpfMapPrunePolicy,
        mode: EbpfWorkerMode,
        worker_name: &'static str,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            info!(
                worker = worker_name,
                enabled = mode.enable_conn || mode.enable_proc || mode.enable_dns,
                ringbuf_requested = mode.native_ringbuf_requested(),
                "eBPF worker facilities requested"
            );

            let runtime = match EbpfService::load_existing_objects() {
                Ok(runtime) => {
                    debug!(
                        conn_obj = ?runtime.conn_obj,
                        proc_obj = ?runtime.proc_obj,
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
                    warn!(worker = worker_name, "eBPF runtime not available: {err}");
                    None
                }
            };

            if mode.enable_dns
                && !mode.enable_proc
                && !mode.enable_conn
                && let Some(runtime) = runtime.as_ref()
                && let Some(dns_obj) = runtime.dns_obj.as_ref()
            {
                match Self::run_dns_explicit_runtime(&bus, &shutdown, dns_obj) {
                    Ok(()) => {
                        info!(worker = worker_name, "explicit DNS eBPF runtime active");
                        return;
                    }
                    Err(err) => {
                        warn!(
                            worker = worker_name,
                            detail = %err,
                            "explicit DNS eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                    }
                }
            }

            let mut state = SupervisorState::default();
            let mut native_ringbuf = if mode.native_ringbuf_requested() {
                match NativeRingbuf::try_open(mode, worker_name) {
                    Ok((consumer, diagnostics)) => {
                        for detail in diagnostics {
                            info!(worker = worker_name, detail = %detail, "native eBPF ringbuf backend fallback detail");
                        }

                        info!(
                            worker = worker_name,
                            backend = ?consumer.backend_kind(),
                            "native eBPF ringbuf consumer enabled"
                        );

                        let _ = crate::workers::dispatch_kernel_event_with_backoff(
                            &bus.kernel_tx,
                            KernelEvent::EbpfProcessMapHit {
                                pid: std::process::id(),
                                uid: 0,
                                note: "native eBPF ringbuf consumer enabled".into(),
                            },
                        );
                        Some(consumer)
                    }
                    Err(err) => {
                        warn!(worker = worker_name, detail = %err, "native eBPF ringbuf consumer unavailable");
                        None
                    }
                }
            } else {
                info!(worker = worker_name, "native eBPF ringbuf not requested for this worker mode");
                None
            };

            let active = mode.enable_conn || mode.enable_proc || mode.enable_dns;
            match (mode.enable_conn, mode.enable_proc, mode.enable_dns) {
                (true, false, false) => {
                    info!(
                        worker = worker_name,
                        conn_active = true,
                        "eBPF worker facilities active"
                    );
                }
                (false, true, false) => {
                    info!(
                        worker = worker_name,
                        proc_ringbuf_active = native_ringbuf.is_some(),
                        "eBPF worker facilities active"
                    );
                }
                (false, false, true) => {
                    info!(
                        worker = worker_name,
                        dns_ringbuf_active = native_ringbuf.is_some(),
                        "eBPF worker facilities active"
                    );
                }
                _ => {
                    info!(
                        worker = worker_name,
                        active,
                        conn_active = mode.enable_conn,
                        proc_ringbuf_active = mode.enable_proc && native_ringbuf.is_some(),
                        dns_ringbuf_active = mode.enable_dns && native_ringbuf.is_some(),
                        "eBPF worker facilities active"
                    );
                }
            }

            if let Some(runtime) = runtime.as_ref() {
                Self::ensure_ebpf_runtime_loaded(runtime, &bus, mode);
            }

            let mut last_conn_supervise = Instant::now()
                .checked_sub(CONN_SUPERVISE_INTERVAL)
                .unwrap_or_else(Instant::now);
            if mode.enable_conn {
                Self::supervise_runtime(&bus, &mut state, prune_policy);
                last_conn_supervise = Instant::now();
            }

            let mut last_reconcile = Instant::now();

            while !shutdown.is_cancelled() {
                if let Some(consumer) = native_ringbuf.as_mut()
                    && let Err(err) = consumer.poll_and_emit(&bus)
                {
                    warn!(worker = worker_name, "native eBPF ringbuf poll failed, disabling consumer: {err}");
                    native_ringbuf = None;
                }

                if last_reconcile.elapsed() >= Duration::from_secs(30) {
                    if let Some(runtime) = runtime.as_ref() {
                        Self::ensure_ebpf_runtime_loaded(runtime, &bus, mode);
                    }
                    last_reconcile = Instant::now();
                }

                if mode.enable_conn && last_conn_supervise.elapsed() >= CONN_SUPERVISE_INTERVAL {
                    Self::supervise_runtime(&bus, &mut state, prune_policy);
                    last_conn_supervise = Instant::now();
                }

                let active_ringbuf =
                    native_ringbuf.is_some() && (mode.enable_proc || mode.enable_dns);
                let loop_delay = if active_ringbuf {
                    EBPFRING_ACTIVE_LOOP_INTERVAL
                } else {
                    CONN_SUPERVISE_INTERVAL
                };
                if crate::workers::sleep_with_shutdown(
                    &shutdown,
                    loop_delay,
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
            }
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_extract_pid_uid(entry: &Value) -> Option<(u32, u32)> {
        ConnectionService::extract_ebpf_map_hit_pid_uid(entry)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_find_numeric(node: &Value, wanted_keys: &[&str]) -> Option<u64> {
        ConnectionService::find_numeric(node, wanted_keys)
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_native_proc_kind(
        sample: &[u8],
    ) -> Option<crate::models::proc_event::ProcEventKind> {
        match Self::parse_native_sample(sample) {
            Some(NativeQueuedEvent::ProcStateChanged(payload)) => Some(payload.kind),
            _ => None,
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_native_proc_payload(sample: &[u8]) -> Option<EbpfProcStatePayload> {
        match Self::parse_native_sample(sample) {
            Some(NativeQueuedEvent::ProcStateChanged(payload)) => Some(payload),
            _ => None,
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_native_dns_payload(sample: &[u8]) -> Option<DnsPayload> {
        match Self::parse_native_sample(sample) {
            Some(NativeQueuedEvent::DnsUpdate(payload)) => Some(payload),
            _ => None,
        }
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_should_emit_dns_sequence(events: &[(&str, &str)]) -> Vec<bool> {
        let mut recent = HashMap::<(String, String), Instant>::new();
        let now = Instant::now();
        events
            .iter()
            .map(|(ip, host)| NativeRingbuf::should_emit_dns_event_at(&mut recent, ip, host, now))
            .collect()
    }
}

impl_restartable_thread_worker_control!(EbpfWorkerControl, "ebpf");

impl EbpfWorkerControl {
    fn ensure_ebpf_runtime_loaded(runtime: &EbpfService, bus: &Bus, mode: EbpfWorkerMode) {
        let Some(bpftool) = resolve_command_path("bpftool") else {
            return;
        };

        if (mode.enable_conn || mode.enable_proc) && !Self::ensure_tracefs_ready() {
            warn!(
                "tracefs not ready; eBPF kprobe/tracepoint attach may fail and trigger worker fallback paths"
            );
        }

        let mut loaded_any = false;

        let has_conn_maps = Path::new("/sys/fs/bpf/opensnitch/tcpMap").exists();
        let has_process_events = Path::new("/sys/fs/bpf/opensnitch_procs/events").exists();
        let has_dns_events = Path::new("/sys/fs/bpf/opensnitch_dns/events").exists();

        if mode.enable_conn
            && let Some(obj) = runtime.conn_obj.as_ref()
            && !has_conn_maps
            && Self::try_load_object_with_bpftool(&bpftool, obj, runtime.conn_pin_root())
        {
            loaded_any = true;
        }

        if mode.enable_proc
            && let Some(obj) = runtime.proc_obj.as_ref()
            && !has_process_events
            && Self::try_load_object_with_bpftool(&bpftool, obj, runtime.proc_pin_root())
        {
            loaded_any = true;
        }

        if mode.enable_dns
            && let Some(obj) = runtime.dns_obj.as_ref()
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

    fn ensure_tracefs_ready() -> bool {
        let tracefs_path = "/sys/kernel/tracing";
        let kprobes_path = "/sys/kernel/tracing/kprobe_events";
        if Path::new(kprobes_path).exists() {
            return true;
        }

        let output = Command::new("mount")
            .args(["-t", "tracefs", "none", tracefs_path])
            .output();

        match output {
            Ok(out) if out.status.success() => Path::new(kprobes_path).exists(),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if !stderr.trim().is_empty() {
                    warn!(detail = %stderr.trim(), "tracefs mount failed");
                }
                Path::new(kprobes_path).exists()
            }
            Err(err) => {
                warn!(detail = %err, "tracefs mount command failed");
                Path::new(kprobes_path).exists()
            }
        }
    }

    fn find_libc_path() -> Option<PathBuf> {
        let maps = fs::read_to_string("/proc/self/maps").ok()?;
        Self::find_libc_path_from_maps(&maps)
    }

    fn find_libc_path_from_maps(maps: &str) -> Option<PathBuf> {
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            if path.contains("libc.so") {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Some(p);
                }
            }
        }
        None
    }

    #[cfg(all(feature = "libbpf-ebpf", feature = "native-ebpf-ringbuf"))]
    fn run_dns_explicit_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        dns_obj: &Path,
    ) -> Result<(), String> {
        use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder, UprobeOpts};

        let libc =
            Self::find_libc_path().ok_or_else(|| "failed to resolve libc path".to_string())?;
        let obj = ObjectBuilder::default()
            .open_file(dns_obj)
            .map_err(|err| format!("open dns object failed ({:?}): {err}", dns_obj))?
            .load()
            .map_err(|err| format!("load dns object failed ({:?}): {err}", dns_obj))?;

        let mut attached = 0usize;
        let mut links = Vec::new();
        for prog in obj.progs_mut() {
            let prog_name = lossy_os(prog.name());
            let attach = match prog_name.as_str() {
                "uretprobe__gethostbyname" => Some(UprobeOpts {
                    retprobe: true,
                    func_name: Some("gethostbyname".to_string()),
                    ..Default::default()
                }),
                "uprobe__getaddrinfo" => Some(UprobeOpts {
                    retprobe: false,
                    func_name: Some("getaddrinfo".to_string()),
                    ..Default::default()
                }),
                "uretprobe__getaddrinfo" => Some(UprobeOpts {
                    retprobe: true,
                    func_name: Some("getaddrinfo".to_string()),
                    ..Default::default()
                }),
                _ => None,
            };

            let Some(opts) = attach else {
                continue;
            };
            match prog.attach_uprobe_with_opts(-1, &libc, 0, opts) {
                Ok(link) => {
                    links.push(link);
                    attached += 1;
                }
                Err(err) => {
                    warn!(program = %prog_name, detail = %err, "explicit DNS uprobe attach failed");
                }
            }
        }

        if attached == 0 {
            return Err("no DNS uprobes attached".to_string());
        }

        let map = obj
            .maps()
            .find(|m| m.name() == "events")
            .ok_or_else(|| "dns object map 'events' not found".to_string())?;

        let queue = Arc::new(Mutex::new(Vec::<Vec<u8>>::with_capacity(128)));
        let queue_closure = Arc::clone(&queue);
        let mut builder = RingBufferBuilder::new();
        builder
            .add(&map, move |sample: &[u8]| -> i32 {
                if let Ok(mut q) = queue_closure.lock() {
                    q.push(sample.to_vec());
                }
                0
            })
            .map_err(|err| format!("dns ringbuf callback registration failed: {err}"))?;
        let ringbuf = builder
            .build()
            .map_err(|err| format!("dns ringbuf build failed: {err}"))?;

        let mut dns_deduper = DnsEbpfEventDeduper::default();
        while !shutdown.is_cancelled() {
            ringbuf
                .poll(Duration::from_millis(100))
                .map_err(|err| format!("dns ringbuf poll failed: {err}"))?;

            let samples = {
                let mut q = queue
                    .lock()
                    .map_err(|_| "dns ringbuf queue lock poisoned".to_string())?;
                q.drain(..).collect::<Vec<_>>()
            };

            for sample in samples {
                let Some(payload) = DnsService::parse_ebpf_dns_sample(&sample) else {
                    continue;
                };
                if !dns_deduper.should_emit(&payload) {
                    continue;
                }
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::DnsUpdate(payload),
                );
            }
        }

        drop(ringbuf);
        drop(links);
        drop(obj);
        Ok(())
    }

    #[cfg(not(all(feature = "libbpf-ebpf", feature = "native-ebpf-ringbuf")))]
    fn run_dns_explicit_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _dns_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit DNS eBPF runtime requires libbpf-ebpf + native-ebpf-ringbuf".to_string())
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

        let Some(bpftool) = resolve_command_path("bpftool") else {
            return;
        };

        let programs = Self::list_programs(&bpftool);
        let maps = Self::list_maps(&bpftool);

        if programs.is_empty() || maps.is_empty() {
            return;
        }

        let opensnitch_programs: Vec<&BpfProgram> = programs
            .iter()
            .filter(|p| p.name.to_lowercase().contains("opensnitch"))
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
                if let Some((pid, uid)) = ConnectionService::extract_ebpf_map_hit_pid_uid(&entry) {
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
                if let Some(v) = parse_hex_token::<u8>(s) {
                    out.push(v);
                }
            }
            _ => {}
        }
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

    fn prune_seen_hits(state: &mut SupervisorState) {
        let ttl = Duration::from_secs(5 * 60);
        state.seen_hits.retain(|_, seen_at| seen_at.elapsed() < ttl);
        trace!(seen_hits = state.seen_hits.len(), "pruned eBPF hit cache");
    }
}

#[cfg(feature = "native-ebpf-ringbuf")]
struct NativeRingbuf {
    consumer: EbpfRingbufConsumer,
    dns_deduper: DnsEbpfEventDeduper,
    mode: EbpfWorkerMode,
}

#[cfg(feature = "native-ebpf-ringbuf")]
#[cfg(feature = "native-ebpf-ringbuf")]
enum NativeQueuedEvent {
    MapHit { pid: u32, uid: u32, note: String },
    ProcStateChanged(EbpfProcStatePayload),
    DnsUpdate(DnsPayload),
}

impl EbpfWorkerControl {
    #[cfg(feature = "native-ebpf-ringbuf")]
    fn parse_native_sample(sample: &[u8]) -> Option<NativeQueuedEvent> {
        if let Some(payload) = Self::parse_dns_sample(sample) {
            return Some(NativeQueuedEvent::DnsUpdate(payload));
        }

        if sample.len() >= ProcessService::EBPF_EXEC_EVENT_LEN {
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
        let pid = read_ne_value_at(sample, 8, u32::from_ne_bytes)?;
        let uid = read_ne_value_at(sample, 12, u32::from_ne_bytes)?;
        if let Some(payload) = ProcessService::parse_ebpf_proc_state_payload(sample) {
            return Some(NativeQueuedEvent::ProcStateChanged(payload));
        }

        let ev_type = read_ne_value_at(sample, 0, u64::from_ne_bytes).unwrap_or_default();
        Some(NativeQueuedEvent::MapHit {
            pid,
            uid,
            note: format!("native ringbuf unknown exec sample type={ev_type}"),
        })
    }

    #[cfg(feature = "native-ebpf-ringbuf")]
    fn parse_dns_sample(sample: &[u8]) -> Option<DnsPayload> {
        DnsService::parse_ebpf_dns_sample(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::EbpfWorkerControl;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn find_libc_path_skips_unmapped_lines() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let temp_path = std::env::temp_dir().join(format!("opensnitchd-libc.so-{unique}"));
        fs::write(&temp_path, b"test").expect("write temp libc path");

        let maps = format!(
            "00400000-00452000 r--p 00000000 00:00 0\n7f1234000000-7f1234100000 r-xp 00000000 08:01 123 {}\n",
            temp_path.display()
        );

        let discovered = EbpfWorkerControl::find_libc_path_from_maps(&maps);
        assert_eq!(discovered, Some(PathBuf::from(&temp_path)));

        let _ = fs::remove_file(temp_path);
    }
}

#[cfg(feature = "native-ebpf-ringbuf")]
impl NativeRingbuf {
    fn try_open(mode: EbpfWorkerMode, worker_name: &'static str) -> Result<(Self, Vec<String>), String> {
        let candidates: Vec<&str> = if mode.enable_proc && mode.enable_dns {
            vec![
                "/sys/fs/bpf/opensnitch_procs/events",
                "/sys/fs/bpf/opensnitch_dns/events",
            ]
        } else if mode.enable_proc {
            vec!["/sys/fs/bpf/opensnitch_procs/events"]
        } else if mode.enable_dns {
            vec!["/sys/fs/bpf/opensnitch_dns/events"]
        } else {
            Vec::new()
        };

        if candidates.is_empty() {
            return Err(format!(
                "native ringbuf path disabled for worker={worker_name} (enable_proc={}, enable_dns={}, enable_conn={})",
                mode.enable_proc, mode.enable_dns, mode.enable_conn
            ));
        }

        let (consumer, diagnostics) = EbpfRingbufConsumer::try_open_with_diagnostics(&candidates)?;

        Ok((
            Self {
                consumer,
                dns_deduper: DnsEbpfEventDeduper::default(),
                mode,
            },
            diagnostics,
        ))
    }

    fn poll_and_emit(&mut self, bus: &Bus) -> Result<(), String> {
        let samples = self.consumer.poll_samples(Duration::from_millis(25))?;

        for sample in samples {
            let Some(event) = EbpfWorkerControl::parse_native_sample(&sample) else {
                continue;
            };
            match event {
                NativeQueuedEvent::MapHit { pid, uid, note } => {
                    if !self.mode.enable_conn {
                        continue;
                    }
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcessMapHit { pid, uid, note },
                    );
                }
                NativeQueuedEvent::ProcStateChanged(payload) => {
                    if !self.mode.enable_proc {
                        continue;
                    }
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcStateChanged(payload),
                    );
                }
                NativeQueuedEvent::DnsUpdate(payload) => {
                    if !self.mode.enable_dns {
                        continue;
                    }
                    if !self.should_emit_dns_event(&payload) {
                        continue;
                    }
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::DnsUpdate(payload),
                    );
                }
            }
        }

        Ok(())
    }

    fn backend_kind(&self) -> &crate::services::ebpf::EbpfRingbufBackendKind {
        self.consumer.backend_kind()
    }

    fn should_emit_dns_event(&mut self, payload: &DnsPayload) -> bool {
        self.dns_deduper.should_emit(payload)
    }

    fn should_emit_dns_event_at(
        recent_events: &mut HashMap<(String, String), Instant>,
        ip: &str,
        host: &str,
        now: Instant,
    ) -> bool {
        DnsEbpfEventDeduper::should_emit_at(recent_events, ip, host, now)
    }
}

#[cfg(not(feature = "native-ebpf-ringbuf"))]
struct NativeRingbuf;

#[cfg(not(feature = "native-ebpf-ringbuf"))]
impl NativeRingbuf {
    fn try_open(_mode: EbpfWorkerMode, _worker_name: &'static str) -> Result<(Self, Vec<String>), String> {
        Err("native-ebpf-ringbuf feature disabled".to_string())
    }

    fn poll_and_emit(&mut self, _bus: &Bus) -> Result<(), String> {
        Ok(())
    }

    fn backend_kind(&self) -> &crate::services::ebpf::EbpfRingbufBackendKind {
        unreachable!("native-ebpf-ringbuf disabled")
    }
}

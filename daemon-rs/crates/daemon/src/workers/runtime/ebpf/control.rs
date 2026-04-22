use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use opensnitch_ebpf_common::maps::EVENTS_MAP_NAME;

use crate::{
    bus::Bus,
    models::dns_payload::DnsPayload,
    models::ebpf_payload::EbpfProcStatePayload,
    models::ebpf_state::BpfMap,
    models::kernel_event::KernelEvent,
    services::{
        connection::ConnectionService,
        dns::{DnsEbpfEventDeduper, DnsService},
        ebpf::{EbpfPinDomain, EbpfRingbufConsumer, EbpfService},
        process::ProcessService,
    },
    tunables::RuntimeTunables,
    utils::byte_read::read_ne_value_at,
    workers::runtime::control::{
        WorkerCommandResult, impl_restartable_thread_worker_control,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsExplicitRuntimeKind {
    #[cfg(feature = "aya-ebpf")]
    Aya,
    Libbpf,
}

#[derive(Debug, Clone, Copy)]
struct DnsExplicitRuntime<'a> {
    kind: DnsExplicitRuntimeKind,
    obj: &'a Path,
}

#[derive(Debug, Clone, Copy)]
struct DnsUprobeSpec {
    program_name: &'static str,
    section_name: &'static str,
    symbol_name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcExplicitRuntimeKind {
    #[cfg(feature = "aya-ebpf")]
    Aya,
}

#[derive(Debug, Clone, Copy)]
struct ProcExplicitRuntime<'a> {
    kind: ProcExplicitRuntimeKind,
    obj: &'a Path,
}

#[derive(Debug, Clone, Copy)]
struct ProcTracepointSpec {
    program_name: &'static str,
    section_name: &'static str,
    category: &'static str,
    name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnExplicitRuntimeKind {
    #[cfg(feature = "aya-ebpf")]
    Aya,
}

#[derive(Debug, Clone, Copy)]
struct ConnExplicitRuntime<'a> {
    kind: ConnExplicitRuntimeKind,
    obj: &'a Path,
}

#[derive(Debug, Clone, Copy)]
struct ConnKprobeSpec {
    program_name: &'static str,
    section_name: &'static str,
    symbol_name: &'static str,
}

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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

            let mut runtime = match EbpfService::load_existing_objects() {
                Ok(runtime) => {
                    debug!(
                        pin_domain = ?runtime.pin_domain(),
                        conn_obj = ?runtime.conn_obj,
                        proc_obj = ?runtime.proc_obj,
                        process_obj = ?runtime.process_obj,
                        dns_obj = ?runtime.dns_obj,
                        rust_dns_obj = ?runtime.rust_dns_obj,
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
                && let Some(explicit_runtime) = Self::select_dns_explicit_runtime(runtime)
            {
                match Self::run_dns_explicit_runtime(&bus, &shutdown, explicit_runtime) {
                    Ok(()) => {
                        info!(worker = worker_name, "explicit DNS eBPF runtime active");
                        return;
                    }
                    Err(err) => {
                        let summary = Self::summarize_bpf_attach_error(&err);
                        warn!(
                            worker = worker_name,
                            detail = %summary,
                            "explicit DNS eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                        debug!(
                            worker = worker_name,
                            detail = %err,
                            "explicit DNS eBPF attach/runtime full verifier output"
                        );
                    }
                }
            }

            if mode.enable_proc
                && !mode.enable_dns
                && !mode.enable_conn
                && let Some(runtime) = runtime.as_ref()
                && let Some(explicit_runtime) = Self::select_proc_explicit_runtime(runtime)
            {
                match Self::run_proc_explicit_runtime(&bus, &shutdown, explicit_runtime) {
                    Ok(()) => {
                        info!(worker = worker_name, "explicit process eBPF runtime active");
                        return;
                    }
                    Err(err) => {
                        warn!(
                            worker = worker_name,
                            detail = %err,
                            "explicit process eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                    }
                }
            }

            if mode.enable_conn
                && !mode.enable_dns
                && !mode.enable_proc
                && let Some(runtime) = runtime.as_ref()
                && let Some(explicit_runtime) = Self::select_conn_explicit_runtime(runtime)
            {
                match Self::run_conn_explicit_runtime(&shutdown, explicit_runtime) {
                    Ok(()) => {
                        info!(worker = worker_name, "explicit connection eBPF runtime active");
                        return;
                    }
                    Err(err) => {
                        warn!(
                            worker = worker_name,
                            detail = %err,
                            "explicit connection eBPF attach/runtime unavailable, continuing with generic eBPF flow"
                        );
                    }
                }
            }

            if let Some(runtime) = runtime.as_mut() {
                Self::ensure_ebpf_runtime_loaded(runtime, &bus, mode);
                #[cfg(feature = "aya-ebpf")]
                runtime.refresh_aya_managed_ringbufs();
            }

            let mut state = SupervisorState::default();
            let mut native_ringbuf = if mode.native_ringbuf_requested() {
                let pin_domain = runtime
                    .as_ref()
                    .map(|runtime| runtime.pin_domain())
                    .unwrap_or_else(EbpfService::selected_pin_domain);
                #[cfg(feature = "aya-ebpf")]
                let managed_aya_ringbuf = runtime
                    .as_mut()
                    .and_then(|runtime| runtime.take_aya_managed_ringbuf(mode.enable_proc, mode.enable_dns));

                match NativeRingbuf::try_open(
                    mode,
                    worker_name,
                    pin_domain,
                    #[cfg(feature = "aya-ebpf")]
                    managed_aya_ringbuf,
                ) {
                    Ok((consumer, diagnostics)) => {
                        for detail in diagnostics {
                            info!(worker = worker_name, detail = %detail, "native eBPF ringbuf backend fallback detail");
                        }

                        info!(
                            worker = worker_name,
                            runtime_mode = ?consumer.runtime_mode(),
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
                    if let Some(runtime) = runtime.as_mut() {
                        Self::ensure_ebpf_runtime_loaded(runtime, &bus, mode);
                        #[cfg(feature = "aya-ebpf")]
                        runtime.refresh_aya_managed_ringbufs();
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

    fn summarize_bpf_attach_error(err: &str) -> String {
        let mut summary = err;
        if let Some((head, _)) = err.split_once("Verifier output:") {
            summary = head.trim();
        }
        if let Some((line, _)) = summary.split_once('\n') {
            summary = line.trim();
        }
        summary.to_string()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_select_dns_explicit_runtime(
        pin_domain: EbpfPinDomain,
        has_legacy_dns_obj: bool,
        has_rust_dns_obj: bool,
    ) -> Option<&'static str> {
        #[cfg(feature = "aya-ebpf")]
        let runtime = Self::select_dns_explicit_runtime_parts(
            pin_domain,
            has_legacy_dns_obj.then_some(Path::new("legacy-dns.o")),
            has_rust_dns_obj.then_some(Path::new("opensnitch-ebpf")),
        );

        #[cfg(not(feature = "aya-ebpf"))]
        let runtime = Self::select_dns_explicit_runtime_parts(
            pin_domain,
            has_legacy_dns_obj.then_some(Path::new("legacy-dns.o")),
        );

        runtime.map(|runtime| match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            DnsExplicitRuntimeKind::Aya => "aya",
            DnsExplicitRuntimeKind::Libbpf => "libbpf",
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_select_proc_explicit_runtime(
        pin_domain: EbpfPinDomain,
        has_rust_ebpf_obj: bool,
    ) -> Option<&'static str> {
        #[cfg(feature = "aya-ebpf")]
        {
            let runtime = Self::select_proc_explicit_runtime_parts(
                pin_domain,
                has_rust_ebpf_obj.then_some(Path::new("opensnitch-ebpf")),
            );
            return runtime.map(|runtime| match runtime.kind {
                ProcExplicitRuntimeKind::Aya => "aya",
            });
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            let _ = pin_domain;
            let _ = has_rust_ebpf_obj;
            None
        }
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
    fn ensure_ebpf_runtime_loaded(_runtime: &mut EbpfService, _bus: &Bus, mode: EbpfWorkerMode) {
        // eBPF object loading is handled natively by the aya/libbpf runtimes.
        // bpftool subprocess loading has been removed; it is not available on minimal
        // distros such as Alpine Linux and OpenWrt.
        if (mode.enable_conn || mode.enable_proc) && !Self::ensure_tracefs_ready() {
            warn!(
                "tracefs not ready; eBPF kprobe/tracepoint attach may fail and trigger worker fallback paths"
            );
        }
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

    fn dns_uprobe_specs() -> &'static [DnsUprobeSpec] {
        &[
            DnsUprobeSpec {
                program_name: "uprobe__gethostbyname",
                section_name: "uprobe/gethostbyname",
                symbol_name: "gethostbyname",
            },
            DnsUprobeSpec {
                program_name: "uretprobe__gethostbyname",
                section_name: "uretprobe/gethostbyname",
                symbol_name: "gethostbyname",
            },
            DnsUprobeSpec {
                program_name: "uprobe__gethostbyname2",
                section_name: "uprobe/gethostbyname2",
                symbol_name: "gethostbyname2",
            },
            DnsUprobeSpec {
                program_name: "uretprobe__gethostbyname2",
                section_name: "uretprobe/gethostbyname2",
                symbol_name: "gethostbyname2",
            },
            DnsUprobeSpec {
                program_name: "uprobe__getaddrinfo",
                section_name: "uprobe/getaddrinfo",
                symbol_name: "getaddrinfo",
            },
            DnsUprobeSpec {
                program_name: "uretprobe__getaddrinfo",
                section_name: "uretprobe/getaddrinfo",
                symbol_name: "getaddrinfo",
            },
        ]
    }

    fn proc_tracepoint_specs() -> &'static [ProcTracepointSpec] {
        &[
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_enter_execve",
                section_name: "tracepoint/syscalls/sys_enter_execve",
                category: "syscalls",
                name: "sys_enter_execve",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_enter_execveat",
                section_name: "tracepoint/syscalls/sys_enter_execveat",
                category: "syscalls",
                name: "sys_enter_execveat",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_exit_execve",
                section_name: "tracepoint/syscalls/sys_exit_execve",
                category: "syscalls",
                name: "sys_exit_execve",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__syscalls_sys_exit_execveat",
                section_name: "tracepoint/syscalls/sys_exit_execveat",
                category: "syscalls",
                name: "sys_exit_execveat",
            },
            ProcTracepointSpec {
                program_name: "tracepoint__sched_sched_process_exit",
                section_name: "tracepoint/sched/sched_process_exit",
                category: "sched",
                name: "sched_process_exit",
            },
        ]
    }

    fn select_dns_explicit_runtime(runtime: &EbpfService) -> Option<DnsExplicitRuntime<'_>> {
        #[cfg(feature = "aya-ebpf")]
        {
            return Self::select_dns_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.dns_obj.as_deref(),
                runtime.rust_dns_obj.as_deref(),
            );
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            Self::select_dns_explicit_runtime_parts(runtime.pin_domain(), runtime.dns_obj.as_deref())
        }
    }

    fn select_proc_explicit_runtime(runtime: &EbpfService) -> Option<ProcExplicitRuntime<'_>> {
        #[cfg(feature = "aya-ebpf")]
        {
            return Self::select_proc_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.rust_dns_obj.as_deref(),
            );
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            let _ = runtime;
            None
        }
    }

    fn conn_kprobe_specs() -> &'static [ConnKprobeSpec] {
        &[
            ConnKprobeSpec {
                program_name: "kprobe__tcp_v4_connect",
                section_name: "kprobe/tcp_v4_connect",
                symbol_name: "tcp_v4_connect",
            },
            ConnKprobeSpec {
                program_name: "kretprobe__tcp_v4_connect",
                section_name: "kretprobe/tcp_v4_connect",
                symbol_name: "tcp_v4_connect",
            },
            ConnKprobeSpec {
                program_name: "kprobe__tcp_v6_connect",
                section_name: "kprobe/tcp_v6_connect",
                symbol_name: "tcp_v6_connect",
            },
            ConnKprobeSpec {
                program_name: "kretprobe__tcp_v6_connect",
                section_name: "kretprobe/tcp_v6_connect",
                symbol_name: "tcp_v6_connect",
            },
            ConnKprobeSpec {
                program_name: "kprobe__udp_sendmsg",
                section_name: "kprobe/udp_sendmsg",
                symbol_name: "udp_sendmsg",
            },
            ConnKprobeSpec {
                program_name: "kprobe__udpv6_sendmsg",
                section_name: "kprobe/udpv6_sendmsg",
                symbol_name: "udpv6_sendmsg",
            },
            ConnKprobeSpec {
                program_name: "kprobe__inet_dgram_connect",
                section_name: "kprobe/inet_dgram_connect",
                symbol_name: "inet_dgram_connect",
            },
            ConnKprobeSpec {
                program_name: "kretprobe__inet_dgram_connect",
                section_name: "kretprobe/inet_dgram_connect",
                symbol_name: "inet_dgram_connect",
            },
            ConnKprobeSpec {
                program_name: "kprobe__udp_tunnel6_xmit_skb",
                section_name: "kprobe/udp_tunnel6_xmit_skb",
                symbol_name: "udp_tunnel6_xmit_skb",
            },
            ConnKprobeSpec {
                program_name: "kprobe__iptunnel_xmit",
                section_name: "kprobe/iptunnel_xmit",
                symbol_name: "iptunnel_xmit",
            },
        ]
    }

    fn select_conn_explicit_runtime(runtime: &EbpfService) -> Option<ConnExplicitRuntime<'_>> {
        #[cfg(feature = "aya-ebpf")]
        {
            return Self::select_conn_explicit_runtime_parts(
                runtime.pin_domain(),
                runtime.rust_dns_obj.as_deref(),
            );
        }

        #[cfg(not(feature = "aya-ebpf"))]
        {
            let _ = runtime;
            None
        }
    }

    #[cfg(feature = "aya-ebpf")]
    fn select_conn_explicit_runtime_parts<'a>(
        pin_domain: EbpfPinDomain,
        rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ConnExplicitRuntime<'a>> {
        if pin_domain == EbpfPinDomain::Aya && let Some(obj) = rust_ebpf_obj {
            return Some(ConnExplicitRuntime {
                kind: ConnExplicitRuntimeKind::Aya,
                obj,
            });
        }

        None
    }

    #[cfg(not(feature = "aya-ebpf"))]
    fn select_conn_explicit_runtime_parts<'a>(
        _pin_domain: EbpfPinDomain,
        _rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ConnExplicitRuntime<'a>> {
        None
    }

    #[cfg(feature = "aya-ebpf")]
    fn select_proc_explicit_runtime_parts<'a>(
        pin_domain: EbpfPinDomain,
        rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ProcExplicitRuntime<'a>> {
        if pin_domain == EbpfPinDomain::Aya && let Some(obj) = rust_ebpf_obj {
            return Some(ProcExplicitRuntime {
                kind: ProcExplicitRuntimeKind::Aya,
                obj,
            });
        }

        None
    }

    #[cfg(not(feature = "aya-ebpf"))]
    fn select_proc_explicit_runtime_parts<'a>(
        _pin_domain: EbpfPinDomain,
        _rust_ebpf_obj: Option<&'a Path>,
    ) -> Option<ProcExplicitRuntime<'a>> {
        None
    }

    #[cfg(feature = "aya-ebpf")]
    fn select_dns_explicit_runtime_parts<'a>(
        pin_domain: EbpfPinDomain,
        legacy_dns_obj: Option<&'a Path>,
        rust_dns_obj: Option<&'a Path>,
    ) -> Option<DnsExplicitRuntime<'a>> {
        if pin_domain == EbpfPinDomain::Aya && let Some(obj) = rust_dns_obj {
            return Some(DnsExplicitRuntime {
                kind: DnsExplicitRuntimeKind::Aya,
                obj,
            });
        }

        legacy_dns_obj.map(|obj| DnsExplicitRuntime {
            kind: DnsExplicitRuntimeKind::Libbpf,
            obj,
        })
    }

    #[cfg(not(feature = "aya-ebpf"))]
    fn select_dns_explicit_runtime_parts<'a>(
        _pin_domain: EbpfPinDomain,
        legacy_dns_obj: Option<&'a Path>,
    ) -> Option<DnsExplicitRuntime<'a>> {
        legacy_dns_obj.map(|obj| DnsExplicitRuntime {
            kind: DnsExplicitRuntimeKind::Libbpf,
            obj,
        })
    }

    fn run_dns_explicit_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        runtime: DnsExplicitRuntime<'_>,
    ) -> Result<(), String> {
        match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            DnsExplicitRuntimeKind::Aya => Self::run_dns_explicit_aya_runtime(bus, shutdown, runtime.obj),
            DnsExplicitRuntimeKind::Libbpf => Self::run_dns_explicit_libbpf_runtime(bus, shutdown, runtime.obj),
        }
    }

    fn run_proc_explicit_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        runtime: ProcExplicitRuntime<'_>,
    ) -> Result<(), String> {
        match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            ProcExplicitRuntimeKind::Aya => {
                Self::run_proc_explicit_aya_runtime(bus, shutdown, runtime.obj)
            }
        }
    }

    fn run_conn_explicit_runtime(
        shutdown: &CancellationToken,
        runtime: ConnExplicitRuntime<'_>,
    ) -> Result<(), String> {
        match runtime.kind {
            #[cfg(feature = "aya-ebpf")]
            ConnExplicitRuntimeKind::Aya => {
                Self::run_conn_explicit_aya_runtime(shutdown, runtime.obj)
            }
        }
    }

    #[cfg(all(feature = "libbpf-ebpf", feature = "native-ebpf-ringbuf"))]
    fn run_dns_explicit_libbpf_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        dns_obj: &Path,
    ) -> Result<(), String> {
        use std::sync::Arc;
        use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder, UprobeOpts};
        use crate::utils::path_text::lossy_os;

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
            let attach = Self::dns_uprobe_specs()
                .iter()
                .find(|spec| spec.program_name == prog_name)
                .map(|spec| UprobeOpts {
                    retprobe: spec.program_name.starts_with("uretprobe__"),
                    func_name: Some(spec.symbol_name.to_string()),
                    ..Default::default()
                });

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
            .find(|m| m.name() == EVENTS_MAP_NAME)
            .ok_or_else(|| format!("dns object map '{}' not found", EVENTS_MAP_NAME))?;

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
    fn run_dns_explicit_libbpf_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _dns_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit DNS eBPF runtime requires libbpf-ebpf + native-ebpf-ringbuf".to_string())
    }

    #[cfg(feature = "aya-ebpf")]
    fn run_dns_explicit_aya_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        dns_obj: &Path,
    ) -> Result<(), String> {
        use std::convert::TryInto;

        use aya::{EbpfLoader, maps::{Map, RingBuf}, programs::UProbe};

        let libc =
            Self::find_libc_path().ok_or_else(|| "failed to resolve libc path".to_string())?;
        let mut bpf = EbpfLoader::new()
            .load_file(dns_obj)
            .map_err(|err| format!("load Rust DNS object failed ({:?}): {err}", dns_obj))?;

        let mut attached = 0usize;
        for spec in Self::dns_uprobe_specs() {
            let lookup_key = if bpf.program(spec.section_name).is_some() {
                spec.section_name
            } else if bpf.program(spec.program_name).is_some() {
                spec.program_name
            } else {
                let available = bpf
                    .programs()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    program = spec.program_name,
                    section = spec.section_name,
                    available = %available,
                    "explicit Rust DNS program not found in object; skipping"
                );
                continue;
            };

            let Some(program_handle) = bpf.program_mut(lookup_key) else {
                warn!(
                    program = spec.program_name,
                    key = lookup_key,
                    "explicit Rust DNS program handle disappeared; skipping"
                );
                continue;
            };

            let program: &mut UProbe = match program_handle.try_into() {
                Ok(program) => program,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        detail = %err,
                        "explicit Rust DNS program type mismatch; skipping"
                    );
                    continue;
                }
            };

            if let Err(err) = program.load() {
                warn!(
                    program = spec.program_name,
                    section = spec.section_name,
                    detail = %err,
                    "explicit Rust DNS program load failed"
                );
                continue;
            }

            match program.attach(Some(spec.symbol_name), 0, &libc, None) {
                Ok(_) => attached += 1,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        symbol = spec.symbol_name,
                        detail = %err,
                        "explicit Rust DNS uprobe attach failed"
                    );
                }
            }
        }

        if attached == 0 {
            return Err("no Rust DNS uprobes attached".to_string());
        }

        if let Some(events_dir) = Path::new(EbpfPinDomain::Aya.dns_events_path()).parent() {
            let _ = fs::create_dir_all(events_dir);
        }
        if !Path::new(EbpfPinDomain::Aya.dns_events_path()).exists() {
            bpf.map_mut(EVENTS_MAP_NAME)
                .ok_or_else(|| format!("Rust DNS object map '{}' not found", EVENTS_MAP_NAME))?
                .pin(EbpfPinDomain::Aya.dns_events_path())
                .map_err(|err| format!("pin Rust DNS events map failed: {err}"))?;
        }

        let map = bpf
            .take_map(EVENTS_MAP_NAME)
            .ok_or_else(|| format!("Rust DNS object map '{}' not found", EVENTS_MAP_NAME))?;
        let map = match map {
            Map::RingBuf(map) => Map::RingBuf(map),
            _ => return Err(format!("Rust DNS object map '{}' is not a ringbuf", EVENTS_MAP_NAME)),
        };
        let mut ringbuf = RingBuf::try_from(map)
            .map_err(|err| format!("Rust DNS ringbuf reader attach failed: {err}"))?;

        let mut dns_deduper = DnsEbpfEventDeduper::default();
        while !shutdown.is_cancelled() {
            let samples = {
                let mut out = Vec::with_capacity(64);
                while let Some(item) = ringbuf.next() {
                    out.push(item.to_vec());
                }
                out
            };

            if samples.is_empty() {
                if crate::workers::sleep_with_shutdown(
                    shutdown,
                    Duration::from_millis(100),
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
                continue;
            }

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
        drop(bpf);
        Ok(())
    }

    #[cfg(feature = "aya-ebpf")]
    fn run_proc_explicit_aya_runtime(
        bus: &Bus,
        shutdown: &CancellationToken,
        proc_obj: &Path,
    ) -> Result<(), String> {
        use std::convert::TryInto;

        use aya::{
            EbpfLoader,
            maps::{Map, RingBuf},
            programs::TracePoint,
        };

        let mut bpf = EbpfLoader::new()
            .load_file(proc_obj)
            .map_err(|err| format!("load Rust process object failed ({:?}): {err}", proc_obj))?;

        let mut attached = 0usize;
        for spec in Self::proc_tracepoint_specs() {
            let lookup_key = if bpf.program(spec.section_name).is_some() {
                spec.section_name
            } else if bpf.program(spec.program_name).is_some() {
                spec.program_name
            } else {
                let available = bpf
                    .programs()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    program = spec.program_name,
                    section = spec.section_name,
                    available = %available,
                    "explicit Rust process program not found in object; skipping"
                );
                continue;
            };

            let Some(program_handle) = bpf.program_mut(lookup_key) else {
                warn!(
                    program = spec.program_name,
                    key = lookup_key,
                    "explicit Rust process program handle disappeared; skipping"
                );
                continue;
            };

            let program: &mut TracePoint = match program_handle.try_into() {
                Ok(program) => program,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        detail = %err,
                        "explicit Rust process program type mismatch; skipping"
                    );
                    continue;
                }
            };

            program.load().map_err(|err| {
                format!(
                    "load Rust process program '{}' failed ({:?}): {err}",
                    spec.program_name, proc_obj
                )
            })?;

            match program.attach(spec.category, spec.name) {
                Ok(_) => attached += 1,
                Err(err) => {
                    warn!(
                        program = spec.program_name,
                        category = spec.category,
                        name = spec.name,
                        detail = %err,
                        "explicit Rust process tracepoint attach failed"
                    );
                }
            }
        }

        if attached == 0 {
            return Err("no Rust process tracepoints attached".to_string());
        }

        info!(
            worker = "ebpf-proc",
            attached,
            "explicit process tracepoints attached"
        );

        let _ = crate::workers::dispatch_kernel_event_with_backoff(
            &bus.kernel_tx,
            KernelEvent::EbpfProcessMapHit {
                pid: std::process::id(),
                uid: 0,
                note: format!("explicit process tracepoints attached count={attached}"),
            },
        );

        if let Some(events_dir) = Path::new(EbpfPinDomain::Aya.proc_events_path()).parent() {
            let _ = fs::create_dir_all(events_dir);
        }
        if !Path::new(EbpfPinDomain::Aya.proc_events_path()).exists() {
            bpf.map_mut(EVENTS_MAP_NAME)
                .ok_or_else(|| format!("Rust process object map '{}' not found", EVENTS_MAP_NAME))?
                .pin(EbpfPinDomain::Aya.proc_events_path())
                .map_err(|err| format!("pin Rust process events map failed: {err}"))?;
        }

        let map = bpf
            .take_map(EVENTS_MAP_NAME)
            .ok_or_else(|| format!("Rust process object map '{}' not found", EVENTS_MAP_NAME))?;
        let map = match map {
            Map::RingBuf(map) => Map::RingBuf(map),
            _ => {
                return Err(format!(
                    "Rust process object map '{}' is not a ringbuf",
                    EVENTS_MAP_NAME
                ));
            }
        };
        let mut ringbuf = RingBuf::try_from(map)
            .map_err(|err| format!("Rust process ringbuf reader attach failed: {err}"))?;

        let mut total_samples: usize = 0;
        let mut parsed_samples: usize = 0;
        let mut rejected_samples: usize = 0;
        let mut first_payload_logged = false;
        let mut last_stats_emit = Instant::now();

        while !shutdown.is_cancelled() {
            let mut samples = 0usize;
            while let Some(item) = ringbuf.next() {
                samples += 1;
                total_samples = total_samples.saturating_add(1);
                trace!(sample_len = item.len(), worker = "ebpf-proc", "explicit process ringbuf sample received");
                if let Some(payload) = ProcessService::parse_ebpf_proc_state_payload(&item) {
                    debug!(
                        worker = "ebpf-proc",
                        sample_len = item.len(),
                        pid = payload.pid,
                        uid = payload.uid,
                        kind = ?payload.kind,
                        "explicit process ringbuf sample parsed"
                    );
                    if !first_payload_logged {
                        info!(
                            worker = "ebpf-proc",
                            pid = payload.pid,
                            uid = payload.uid,
                            ppid = payload.ppid,
                            kind = ?payload.kind,
                            comm = payload.comm,
                            exe = payload.exe,
                            args = ?payload.args,
                            args_partial = payload.args_partial,
                            ret_code = payload.ret_code,
                            "native eBPF process state event received"
                        );
                        first_payload_logged = true;
                    }
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::EbpfProcStateChanged(payload),
                    );
                    parsed_samples = parsed_samples.saturating_add(1);
                } else {
                    let ev_type = read_ne_value_at(&item, 0, u64::from_ne_bytes).unwrap_or_default();
                    debug!(
                        worker = "ebpf-proc",
                        sample_len = item.len(),
                        ev_type,
                        expected_len = ProcessService::EBPF_EXEC_EVENT_LEN,
                        "explicit process ringbuf sample rejected by parser"
                    );
                    rejected_samples = rejected_samples.saturating_add(1);
                }
            }

            if last_stats_emit.elapsed() >= Duration::from_secs(2) {
                info!(
                    worker = "ebpf-proc",
                    total_samples,
                    parsed_samples,
                    rejected_samples,
                    "explicit process ringbuf sample stats"
                );
                let note = format!(
                    "explicit process ringbuf parse stats parsed={} rejected={}",
                    parsed_samples, rejected_samples
                );
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::EbpfProcessMapHit {
                        pid: std::process::id(),
                        uid: 0,
                        note,
                    },
                );
                last_stats_emit = Instant::now();
            }

            if samples == 0
                && crate::workers::sleep_with_shutdown(
                    shutdown,
                    Duration::from_millis(100),
                    SHUTDOWN_POLL_INTERVAL,
                )
            {
                break;
            }
        }

        drop(ringbuf);
        drop(bpf);
        Ok(())
    }

    #[cfg(not(feature = "aya-ebpf"))]
    fn run_proc_explicit_aya_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _proc_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit Rust process eBPF runtime requires aya-ebpf".to_string())
    }

    #[cfg(not(feature = "aya-ebpf"))]
    fn run_dns_explicit_aya_runtime(
        _bus: &Bus,
        _shutdown: &CancellationToken,
        _dns_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit Rust DNS eBPF runtime requires aya-ebpf".to_string())
    }

    #[cfg(feature = "aya-ebpf")]
    fn run_conn_explicit_aya_runtime(
        shutdown: &CancellationToken,
        conn_obj: &Path,
    ) -> Result<(), String> {
        use std::convert::TryInto;

        use aya::{EbpfLoader, programs::KProbe};

        let mut bpf = EbpfLoader::new()
            .load_file(conn_obj)
            .map_err(|err| format!("load Rust connection object failed ({:?}): {err}", conn_obj))?;

        let mut attached = 0usize;
        let mut tunnel_expected = 0usize;
        let mut tunnel_attached = 0usize;
        for spec in Self::conn_kprobe_specs() {
            let is_tunnel = matches!(spec.symbol_name, "udp_tunnel6_xmit_skb" | "iptunnel_xmit");
            if is_tunnel {
                tunnel_expected += 1;
            }

            let lookup_key = if bpf.program(spec.section_name).is_some() {
                spec.section_name
            } else if bpf.program(spec.program_name).is_some() {
                spec.program_name
            } else {
                if is_tunnel {
                    warn!(
                        symbol = spec.symbol_name,
                        section = spec.section_name,
                        program = spec.program_name,
                        "connection tunnel probe not found in Aya object"
                    );
                }
                continue;
            };

            let Some(program_handle) = bpf.program_mut(lookup_key) else {
                if is_tunnel {
                    warn!(symbol = spec.symbol_name, "connection tunnel probe handle missing");
                }
                continue;
            };

            let program: &mut KProbe = match program_handle.try_into() {
                Ok(program) => program,
                Err(_) => {
                    if is_tunnel {
                        warn!(
                            symbol = spec.symbol_name,
                            "connection tunnel probe is not an Aya KProbe"
                        );
                    }
                    continue;
                }
            };

            if let Err(err) = program.load() {
                if is_tunnel {
                    warn!(symbol = spec.symbol_name, detail = %err, "connection tunnel probe load failed");
                }
                continue;
            }

            if program.attach(spec.symbol_name, 0).is_ok() {
                attached += 1;
                if is_tunnel {
                    tunnel_attached += 1;
                }
            } else if is_tunnel {
                warn!(
                    symbol = spec.symbol_name,
                    "connection tunnel probe attach failed"
                );
            }
        }

        info!(
            attached,
            total = Self::conn_kprobe_specs().len(),
            tunnel_attached,
            tunnel_expected,
            "explicit Aya connection kprobe attach summary"
        );

        if tunnel_expected > 0 && tunnel_attached == 0 {
            warn!(
                "no connection tunnel probes were attached; tunnel parity checks may be incomplete on this host"
            );
        }

        if attached == 0 {
            return Err("no Rust connection kprobes attached".to_string());
        }

        let _ = fs::create_dir_all(EbpfPinDomain::Aya.conn_root());
        if !Path::new(EbpfPinDomain::Aya.conn_tcp_map_path()).exists() {
            bpf.map_mut("tcpMap")
                .ok_or_else(|| "Rust connection object map 'tcpMap' not found".to_string())?
                .pin(EbpfPinDomain::Aya.conn_tcp_map_path())
                .map_err(|err| format!("pin Rust connection tcpMap failed: {err}"))?;
        }

        while !shutdown.is_cancelled() {
            if crate::workers::sleep_with_shutdown(
                shutdown,
                Duration::from_millis(250),
                SHUTDOWN_POLL_INTERVAL,
            ) {
                break;
            }
        }

        drop(bpf);
        Ok(())
    }

    #[cfg(not(feature = "aya-ebpf"))]
    fn run_conn_explicit_aya_runtime(
        _shutdown: &CancellationToken,
        _conn_obj: &Path,
    ) -> Result<(), String> {
        Err("explicit Rust connection eBPF runtime requires aya-ebpf".to_string())
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

        #[cfg(feature = "aya-ebpf")]
        Self::supervise_runtime_aya(bus, state, prune_policy);
    }

    /// Aya-native supervisor: enumerates loaded kernel programs/maps via the BPF syscall
    /// iterators (no bpftool subprocess required) and performs typed map prune + hit events.
    #[cfg(feature = "aya-ebpf")]
    fn supervise_runtime_aya(
        bus: &Bus,
        state: &mut SupervisorState,
        prune_policy: EbpfMapPrunePolicy,
    ) {
        use aya::maps::loaded_maps;
        use aya::programs::loaded_programs;

        // Collect map IDs associated with opensnitch-named programs.
        let opensnitch_map_ids: HashSet<u32> = loaded_programs()
            .flatten()
            .filter(|p| {
                p.name_as_str()
                    .map(|n| n.to_lowercase().contains("opensnitch"))
                    .unwrap_or(false)
            })
            .filter_map(|p| p.map_ids().ok().flatten())
            .flatten()
            .collect();

        if opensnitch_map_ids.is_empty() {
            return;
        }

        // Resolve name + max_entries for each relevant map.
        let map_metas: HashMap<u32, (String, u32)> = loaded_maps()
            .flatten()
            .filter(|m| opensnitch_map_ids.contains(&m.id()))
            .map(|m| {
                let name = m.name_as_str().unwrap_or("").to_string();
                (m.id(), (name, m.max_entries()))
            })
            .collect();

        let opensnitch_map_count = opensnitch_map_ids.len();

        for map_id in opensnitch_map_ids {
            let Some((map_name, max_entries)) = map_metas.get(&map_id) else {
                continue;
            };

            // Try v4 key (12 bytes) first, then v6 key (36 bytes).
            let (hits, deleted, entry_count) =
                Self::aya_inspect_and_prune_map::<12>(map_id, *max_entries, prune_policy)
                    .or_else(|| {
                        Self::aya_inspect_and_prune_map::<36>(map_id, *max_entries, prune_policy)
                    })
                    .unwrap_or_default();

            let bpf_map_meta = BpfMap { id: map_id, name: map_name.clone(), max_entries: *max_entries };
            Self::maybe_emit_pressure(bus, state, &bpf_map_meta, entry_count);

            if deleted > 0 {
                let _ = crate::workers::dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::EbpfProcessMapHit {
                        pid: std::process::id(),
                        uid: 0,
                        note: format!(
                            "eBPF map '{}' (id={map_id}) pruned {deleted} entries under pressure",
                            map_name
                        ),
                    },
                );
            }

            for (pid, uid) in hits {
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
                                map_name
                            ),
                        },
                    );
                }
            }
        }

        let _ = crate::workers::dispatch_kernel_event_with_backoff(
            &bus.kernel_tx,
            KernelEvent::EbpfProcessMapHit {
                pid: std::process::id(),
                uid: 0,
                note: format!(
                    "aya supervisor active: {opensnitch_map_count} opensnitch maps monitored"
                ),
            },
        );
    }

    /// Inspect and prune a BPF HashMap with a fixed key size of `N` bytes.
    ///
    /// Returns `Some((hits, deleted, entry_count))` if the map can be opened as
    /// `HashMap<[u8; N], [u8; 16]>`, or `None` if the key/value size does not match.
    /// `hits` contains `(pid, uid)` pairs extracted from each map value.
    #[cfg(feature = "aya-ebpf")]
    fn aya_inspect_and_prune_map<const N: usize>(
        map_id: u32,
        max_entries: u32,
        policy: EbpfMapPrunePolicy,
    ) -> Option<(Vec<(u32, u32)>, usize, u32)>
    where
        [u8; N]: aya::Pod,
    {
        use aya::maps::{HashMap as AyaHashMap, Map, MapData};

        let map_data = MapData::from_id(map_id).ok()?;
        let mut map: AyaHashMap<_, [u8; N], [u8; 16]> = Map::HashMap(map_data).try_into().ok()?;

        let mut all_keys: Vec<[u8; N]> = Vec::new();
        let mut hits: Vec<(u32, u32)> = Vec::new();

        for result in map.iter() {
            let Ok((key, value)) = result else { continue };
            let pid = u64::from_ne_bytes(value[0..8].try_into().unwrap()) as u32;
            let uid = u64::from_ne_bytes(value[8..16].try_into().unwrap()) as u32;
            hits.push((pid, uid));
            all_keys.push(key);
        }

        let entry_count = all_keys.len() as u32;

        let deleted = if policy.enabled && max_entries > 0 {
            let threshold_count =
                ((max_entries as usize * policy.threshold_percent) + 99) / 100;
            if entry_count as usize > threshold_count {
                let target_count = (max_entries as usize * policy.target_percent) / 100;
                let delete_budget = (entry_count as usize).saturating_sub(target_count);
                let mut deleted = 0;
                for key in all_keys.iter().take(delete_budget) {
                    if map.remove(key).is_ok() {
                        deleted += 1;
                    }
                }
                if deleted > 0 {
                    debug!(
                        map_id,
                        deleted,
                        entry_count,
                        max_entries,
                        threshold_percent = policy.threshold_percent,
                        target_percent = policy.target_percent,
                        "eBPF map prune applied (aya)"
                    );
                }
                deleted
            } else {
                0
            }
        } else {
            0
        };

        Some((hits, deleted, entry_count))
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
#[path = "../../../tests/workers/ebpf_control.rs"]
mod tests;

#[cfg(feature = "native-ebpf-ringbuf")]
impl NativeRingbuf {
    fn try_open(
        mode: EbpfWorkerMode,
        worker_name: &'static str,
        pin_domain: EbpfPinDomain,
        #[cfg(feature = "aya-ebpf")] managed_aya_ringbuf: Option<crate::services::ebpf::AyaManagedRingbufAsset>,
    ) -> Result<(Self, Vec<String>), String> {
        let managed_candidates = pin_domain.native_ringbuf_candidates(mode.enable_proc, mode.enable_dns);
        let legacy_candidates = EbpfPinDomain::Legacy
            .native_ringbuf_candidates(mode.enable_proc, mode.enable_dns);

        if managed_candidates.is_empty() && legacy_candidates.is_empty() {
            return Err(format!(
                "native ringbuf path disabled for worker={worker_name} (enable_proc={}, enable_dns={}, enable_conn={})",
                mode.enable_proc, mode.enable_dns, mode.enable_conn
            ));
        }

        let (consumer, diagnostics) = EbpfRingbufConsumer::try_open_with_diagnostics(
            pin_domain,
            #[cfg(feature = "aya-ebpf")]
            managed_aya_ringbuf,
            &managed_candidates,
            &legacy_candidates,
        )?;

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

    fn runtime_mode(&self) -> crate::services::ebpf::EbpfRuntimeMode {
        self.consumer.runtime_mode()
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
    fn try_open(
        _mode: EbpfWorkerMode,
        _worker_name: &'static str,
        _pin_domain: EbpfPinDomain,
        #[cfg(feature = "aya-ebpf")] _managed_aya_ringbuf: Option<crate::services::ebpf::AyaManagedRingbufAsset>,
    ) -> Result<(Self, Vec<String>), String> {
        Err("native-ebpf-ringbuf feature disabled".to_string())
    }

    fn poll_and_emit(&mut self, _bus: &Bus) -> Result<(), String> {
        Ok(())
    }

    fn backend_kind(&self) -> &crate::services::ebpf::EbpfRingbufBackendKind {
        unreachable!("native-ebpf-ringbuf disabled")
    }
}

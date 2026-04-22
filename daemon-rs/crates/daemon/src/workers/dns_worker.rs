use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};

use regex::Regex;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
    bus::Bus,
    models::kernel_event::KernelEvent,
    services::ebpf_runtime_service::EbpfRuntimeService,
    utils::command_path::command_exists,
    workers::{
        KernelEventDispatch,
        control::{
            WorkerCommand, WorkerCommandResult, WorkerControl, WorkerJoinStatus, WorkerState,
        },
        dispatch_kernel_event_with_backoff,
    },
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CHILD_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const RESOLVED_VARLINK_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
const RESOLVED_VARLINK_METHOD: &str = "io.systemd.Resolve.Monitor.SubscribeQueryResults";
static DNS_EBPF_HOOK_UNSUPPORTED: AtomicBool = AtomicBool::new(false);
static DNS_MONITOR_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const RESOLVED_STATE_SUCCESS: &str = "success";
const DNS_TYPE_A: u64 = 1;
const DNS_TYPE_CNAME: u64 = 5;
const DNS_TYPE_AAAA: u64 = 28;

const DNS_MONITOR_STATE_IDLE: u8 = 0;
const DNS_MONITOR_STATE_VARLINK_CONNECTING: u8 = 1;
const DNS_MONITOR_STATE_VARLINK_SUBSCRIBED: u8 = 2;
const DNS_MONITOR_STATE_VARLINK_DISCONNECTED: u8 = 3;
const DNS_MONITOR_STATE_VARLINK_ERROR: u8 = 4;
const DNS_MONITOR_STATE_FALLBACK_RESOLVECTL: u8 = 5;
const DNS_MONITOR_STATE_FALLBACK_DISCONNECTED: u8 = 6;
const DNS_MONITOR_STATE_STOPPED: u8 = 7;

fn set_dns_monitor_state(state: u8) {
    let previous = DNS_MONITOR_STATE.swap(state, Ordering::Relaxed);
    if previous == state {
        return;
    }

    let label = dns_monitor_state_label();
    crate::utils::systemd_notify::status(&format!("DNS monitor state: {label}"));
}

pub(crate) fn dns_monitor_state_label() -> &'static str {
    match DNS_MONITOR_STATE.load(Ordering::Relaxed) {
        DNS_MONITOR_STATE_IDLE => "idle",
        DNS_MONITOR_STATE_VARLINK_CONNECTING => "varlink-connecting",
        DNS_MONITOR_STATE_VARLINK_SUBSCRIBED => "varlink-subscribed",
        DNS_MONITOR_STATE_VARLINK_DISCONNECTED => "varlink-disconnected",
        DNS_MONITOR_STATE_VARLINK_ERROR => "varlink-error",
        DNS_MONITOR_STATE_FALLBACK_RESOLVECTL => "resolvectl-fallback",
        DNS_MONITOR_STATE_FALLBACK_DISCONNECTED => "resolvectl-disconnected",
        DNS_MONITOR_STATE_STOPPED => "stopped",
        _ => "unknown",
    }
}

struct DnsWorkerRuntime {
    shutdown: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

pub struct DnsWorkerControl {
    bus: Bus,
    daemon_shutdown: CancellationToken,
    runtime: Mutex<DnsWorkerRuntime>,
}

impl DnsWorkerControl {
    pub fn new(bus: Bus, daemon_shutdown: CancellationToken) -> Self {
        let worker_shutdown = daemon_shutdown.child_token();
        let handle = Self::spawn_worker_thread(bus.clone(), worker_shutdown.clone());
        Self {
            bus,
            daemon_shutdown,
            runtime: Mutex::new(DnsWorkerRuntime {
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
            ));
        }

        WorkerCommandResult::Applied
    }

    fn spawn_worker_thread(bus: Bus, shutdown: CancellationToken) -> JoinHandle<()> {
        thread::spawn(move || {
            let monitor_shutdown = shutdown.clone();
            let monitor_bus = bus.clone();
            let monitor_handle = thread::spawn(move || {
                run_systemd_resolved_monitor(monitor_bus, monitor_shutdown);
            });

            let ebpf_shutdown = shutdown.clone();
            let ebpf_bus = bus.clone();
            let ebpf_handle = thread::spawn(move || {
                run_dns_ebpf_monitor(ebpf_bus, ebpf_shutdown);
            });

            let mut last_mtime: Option<SystemTime> = None;

            while !shutdown.is_cancelled() {
                let meta = fs::metadata("/etc/hosts");
                let current_mtime = meta.ok().and_then(|m| m.modified().ok());
                let changed = current_mtime.is_some() && current_mtime != last_mtime;

                if changed {
                    last_mtime = current_mtime;
                    if let Ok(contents) = fs::read_to_string("/etc/hosts") {
                        for line in contents.lines() {
                            let trimmed = line.trim();
                            if trimmed.is_empty() || trimmed.starts_with('#') {
                                continue;
                            }

                            let fields: Vec<&str> = trimmed.split_whitespace().collect();
                            if fields.len() < 2 {
                                continue;
                            }

                            let ip = fields[0].to_string();
                            for host in fields.iter().skip(1) {
                                if host.starts_with('#') {
                                    break;
                                }
                                let event = KernelEvent::DnsResolved {
                                    ip: ip.clone(),
                                    host: (*host).to_string(),
                                };
                                if matches!(
                                    dispatch_kernel_event_with_backoff(&bus.kernel_tx, event),
                                    KernelEventDispatch::ChannelClosed
                                ) {
                                    debug!("dns worker stopping: kernel channel closed");
                                    return;
                                }
                            }
                        }
                    }
                }

                if sleep_with_shutdown(&shutdown, Duration::from_secs(30)) {
                    break;
                }
            }

            join_with_timeout("dns-systemd-monitor", monitor_handle, CHILD_JOIN_TIMEOUT);
            join_with_timeout("dns-ebpf-monitor", ebpf_handle, CHILD_JOIN_TIMEOUT);
        })
    }
}

impl WorkerControl for DnsWorkerControl {
    fn worker_name(&self) -> &'static str {
        "dns"
    }

    fn control(&self, command: WorkerCommand) -> WorkerCommandResult {
        match command {
            WorkerCommand::Stop => self.stop_worker(),
            WorkerCommand::Start => self.spawn_once(),
            WorkerCommand::Probe => WorkerCommandResult::Applied,
        }
    }

    fn spawn_once(&self) -> WorkerCommandResult {
        self.start_worker()
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

fn run_dns_ebpf_monitor(_bus: Bus, shutdown: CancellationToken) {
    if !command_exists("bpftool") {
        return;
    }

    while !shutdown.is_cancelled() {
        ensure_dns_ebpf_hook_loaded();

        let bus = _bus.clone();
        if let Some(mut consumer) = DnsEbpfRingbuf::try_open() {
            while !shutdown.is_cancelled() {
                if let Err(err) = consumer.poll_and_emit(&bus) {
                    warn!("dns eBPF ringbuf poll failed: {err}");
                    break;
                }
            }
        }

        if sleep_with_shutdown(&shutdown, Duration::from_secs(2)) {
            break;
        }
    }
}

fn ensure_dns_ebpf_hook_loaded() {
    if DNS_EBPF_HOOK_UNSUPPORTED.load(Ordering::Relaxed) {
        return;
    }

    if Path::new("/sys/fs/bpf/opensnitch_dns/events").exists() {
        return;
    }

    let runtime = match EbpfRuntimeService::load_existing_objects() {
        Ok(rt) => rt,
        Err(_) => return,
    };

    let Some(obj) = runtime.dns_obj.as_ref() else {
        return;
    };

    let _ = fs::create_dir_all("/sys/fs/bpf/opensnitch_dns");
    let obj = obj.to_string_lossy().to_string();

    let attempts: &[&[&str]] = &[
        &[
            "prog",
            "loadall",
            &obj,
            "/sys/fs/bpf/opensnitch_dns",
            "autoattach",
        ],
        &["prog", "loadall", &obj, "/sys/fs/bpf/opensnitch_dns"],
    ];

    for args in attempts {
        let stderr = match Command::new("bpftool").args(*args).output() {
            Ok(output) if output.status.success() => break,
            Ok(output) => String::from_utf8_lossy(&output.stderr).to_string(),
            Err(_) => String::new(),
        };

        if stderr.contains("failed to pin at") && stderr.contains("-EEXIST") {
            return;
        }

        if stderr.contains("missing ':function[+offset]' specification")
            || stderr.contains("does not support autoattach")
            || stderr.contains("failed to pin all programs")
        {
            DNS_EBPF_HOOK_UNSUPPORTED.store(true, Ordering::Relaxed);
            warn!(
                "dns eBPF hook disabled: kernel/libbpf does not support this probe format; using non-eBPF DNS monitors"
            );
            return;
        }
    }
}

fn run_systemd_resolved_monitor(bus: Bus, shutdown: CancellationToken) {
    set_dns_monitor_state(DNS_MONITOR_STATE_IDLE);
    while !shutdown.is_cancelled() {
        if Path::new(RESOLVED_VARLINK_SOCKET).exists() {
            set_dns_monitor_state(DNS_MONITOR_STATE_VARLINK_CONNECTING);
            debug!(
                socket = RESOLVED_VARLINK_SOCKET,
                "[DNS] using systemd-resolved varlink monitor"
            );
            match run_systemd_resolved_varlink_session(&bus, &shutdown) {
                Ok(()) => {}
                Err(err) => {
                    set_dns_monitor_state(DNS_MONITOR_STATE_VARLINK_ERROR);
                    warn!("dns worker: systemd-resolved varlink monitor failed: {err}");
                }
            }
        }

        if shutdown.is_cancelled() {
            break;
        }

        if command_exists("resolvectl") {
            set_dns_monitor_state(DNS_MONITOR_STATE_FALLBACK_RESOLVECTL);
            debug!("[DNS] using resolvectl monitor fallback");
            run_resolvectl_monitor_session(&bus, &shutdown);
        }

        if sleep_with_shutdown(&shutdown, Duration::from_secs(2)) {
            break;
        }
    }
    set_dns_monitor_state(DNS_MONITOR_STATE_STOPPED);
}

fn run_systemd_resolved_varlink_session(
    bus: &Bus,
    shutdown: &CancellationToken,
) -> Result<(), String> {
    debug!(
        socket = RESOLVED_VARLINK_SOCKET,
        "[DNS] connecting to systemd-resolved varlink"
    );
    let mut stream = UnixStream::connect(RESOLVED_VARLINK_SOCKET)
        .map_err(|err| format!("failed to connect to {RESOLVED_VARLINK_SOCKET}: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|err| format!("failed to configure varlink read timeout: {err}"))?;

    let subscribe_request = serde_json::json!({
        "method": RESOLVED_VARLINK_METHOD,
        "parameters": {},
        "more": true,
    });
    let mut request = subscribe_request.to_string().into_bytes();
    request.push(0);
    stream
        .write_all(&request)
        .map_err(|err| format!("failed to send varlink subscribe request: {err}"))?;
    set_dns_monitor_state(DNS_MONITOR_STATE_VARLINK_SUBSCRIBED);
    info!("[DNS] subscribed to systemd-resolved monitor events");

    let mut buf = vec![0_u8; 8192];
    let mut pending: Vec<u8> = Vec::with_capacity(8192);

    while !shutdown.is_cancelled() {
        match stream.read(&mut buf) {
            Ok(0) => {
                set_dns_monitor_state(DNS_MONITOR_STATE_VARLINK_DISCONNECTED);
                debug!("[DNS] systemd-resolved varlink monitor disconnected");
                break;
            }
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);

                while let Some(pos) = pending.iter().position(|b| *b == 0 || *b == b'\n') {
                    let msg = pending.drain(..=pos).collect::<Vec<u8>>();
                    if msg.is_empty() {
                        continue;
                    }

                    let payload = msg
                        .iter()
                        .copied()
                        .take_while(|b| *b != 0 && *b != b'\n')
                        .collect::<Vec<u8>>();
                    if payload.is_empty() {
                        continue;
                    }

                    if let Ok(value) = serde_json::from_slice::<Value>(&payload) {
                        parse_and_emit_resolved_varlink_message(bus, &value);
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(err) => return Err(format!("varlink read failed: {err}")),
        }
    }

    if shutdown.is_cancelled() {
        set_dns_monitor_state(DNS_MONITOR_STATE_STOPPED);
        info!("[DNS] systemd-resolved monitor stopped");
    }

    Ok(())
}

fn parse_and_emit_resolved_varlink_message(bus: &Bus, value: &Value) {
    for (ip, host) in extract_dns_events_from_varlink(value) {
        trace!(ip = %ip, host = %host, "[DNS] systemd-resolved event");
        let _ = dispatch_kernel_event_with_backoff(
            &bus.kernel_tx,
            KernelEvent::DnsResolved { ip, host },
        );
    }
}

pub(crate) fn extract_dns_events_from_varlink(value: &Value) -> Vec<(String, String)> {
    let payload = value.get("parameters").unwrap_or(value);

    // Match Go systemd-resolved path: only accept successful responses.
    let is_success = payload
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case(RESOLVED_STATE_SUCCESS));
    if !is_success {
        return Vec::new();
    }

    let Some(answers) = payload.get("answer").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut events = Vec::new();
    for answer in answers {
        let rr = answer.get("rr").unwrap_or(answer);
        let rr_type = rr
            .get("key")
            .and_then(|key| key.get("type"))
            .and_then(Value::as_u64);

        // Keep parity with Go: only A/AAAA/CNAME records are tracked.
        if !matches!(rr_type, Some(DNS_TYPE_A | DNS_TYPE_AAAA | DNS_TYPE_CNAME)) {
            continue;
        }

        let key_name = rr
            .get("key")
            .and_then(|key| key.get("name"))
            .and_then(Value::as_str)
            .map(|name| name.trim_end_matches('.').to_string());

        if let Some(address_bytes) = rr.get("address").and_then(Value::as_array) {
            let ip = decode_varlink_ip(address_bytes);
            if let (Some(ip), Some(host)) = (ip, key_name.as_ref()) {
                events.push((ip, host.clone()));
            }
            continue;
        }

        let cname = rr
            .get("name")
            .and_then(Value::as_str)
            .map(|value| value.trim_end_matches('.').to_string());

        if let (Some(alias), Some(canonical)) = (key_name.as_ref(), cname.as_ref()) {
            events.push((canonical.clone(), alias.clone()));
        }
    }

    events
}

pub(crate) fn decode_varlink_ip(bytes: &[Value]) -> Option<String> {
    let parsed = bytes
        .iter()
        .map(|value| value.as_u64().and_then(|num| u8::try_from(num).ok()))
        .collect::<Option<Vec<u8>>>()?;

    match parsed.len() {
        4 => Some(std::net::Ipv4Addr::new(parsed[0], parsed[1], parsed[2], parsed[3]).to_string()),
        16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&parsed);
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

fn run_resolvectl_monitor_session(bus: &Bus, shutdown: &CancellationToken) {
    let re_a = Regex::new(r"(?i)\b([^\s]+)\s+IN\s+(A|AAAA)\s+([0-9a-f:.]+)\b").ok();
    let re_cname = Regex::new(r"(?i)\b([^\s]+)\s+IN\s+CNAME\s+([^\s]+)\b").ok();

    let mut child = match Command::new("resolvectl")
        .args(["monitor"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            warn!("dns worker: unable to start resolvectl monitor: {err}");
            return;
        }
    };
    info!("[DNS] subscribed via resolvectl monitor fallback");

    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return;
    };

    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        if shutdown.is_cancelled() {
            let _ = child.kill();
            break;
        }

        let Ok(line) = line else {
            break;
        };

        if let Some(re) = &re_a
            && let Some(caps) = re.captures(&line)
        {
            let host = caps.get(1).map(|m| m.as_str().trim_end_matches('.'));
            let ip = caps.get(3).map(|m| m.as_str());
            if let (Some(host), Some(ip)) = (host, ip) {
                trace!(ip, host, "[DNS] resolvectl A/AAAA event");
                let _ = dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::DnsResolved {
                        ip: ip.to_string(),
                        host: host.to_string(),
                    },
                );
            }
            continue;
        }

        if let Some(re) = &re_cname
            && let Some(caps) = re.captures(&line)
        {
            let alias = caps.get(1).map(|m| m.as_str().trim_end_matches('.'));
            let canonical = caps.get(2).map(|m| m.as_str().trim_end_matches('.'));
            if let (Some(alias), Some(canonical)) = (alias, canonical) {
                trace!(alias, canonical, "[DNS] resolvectl CNAME event");
                let _ = dispatch_kernel_event_with_backoff(
                    &bus.kernel_tx,
                    KernelEvent::DnsResolved {
                        ip: canonical.to_string(),
                        host: alias.to_string(),
                    },
                );
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    if shutdown.is_cancelled() {
        set_dns_monitor_state(DNS_MONITOR_STATE_STOPPED);
        info!("[DNS] resolvectl monitor stopped");
    } else {
        set_dns_monitor_state(DNS_MONITOR_STATE_FALLBACK_DISCONNECTED);
        debug!("[DNS] resolvectl monitor disconnected");
    }
}

fn sleep_with_shutdown(shutdown: &CancellationToken, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while !shutdown.is_cancelled() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }

        let remaining = deadline.saturating_duration_since(now);
        thread::sleep(remaining.min(SHUTDOWN_POLL_INTERVAL));
    }

    true
}

fn join_with_timeout(name: &str, handle: JoinHandle<()>, timeout: Duration) {
    let started = Instant::now();
    while !handle.is_finished() && started.elapsed() < timeout {
        thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }

    if !handle.is_finished() {
        warn!(
            "{} thread did not stop within {:?}; detaching",
            name, timeout
        );
        return;
    }

    let _ = handle.join();
}

struct DnsEbpfRingbuf {
    _map: &'static mut libbpf_rs::MapHandle,
    ringbuf: libbpf_rs::RingBuffer<'static>,
    queue: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

trait DnsRingbufSampleExt {
    fn parse_dns_ringbuf_sample(&self) -> Option<(String, String)>;
}

impl DnsRingbufSampleExt for [u8] {
    fn parse_dns_ringbuf_sample(&self) -> Option<(String, String)> {
        const DNS_EVENT_LEN: usize = 4 + 16 + 252;
        if self.len() != DNS_EVENT_LEN {
            return None;
        }

        let addr_type = u32::from_ne_bytes([self[0], self[1], self[2], self[3]]);
        if addr_type != 2 && addr_type != 10 {
            return None;
        }

        let ip_bytes = &self[4..20];
        let host_bytes = &self[20..272];
        let host_end = host_bytes
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(host_bytes.len());
        let host = String::from_utf8_lossy(&host_bytes[..host_end]).to_string();
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
}

impl DnsEbpfRingbuf {
    fn try_open() -> Option<Self> {
        let map =
            libbpf_rs::MapHandle::from_pinned_path("/sys/fs/bpf/opensnitch_dns/events").ok()?;
        let map = Box::leak(Box::new(map));

        let queue = std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(64)));
        let queue_closure = std::sync::Arc::clone(&queue);

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(map, move |sample: &[u8]| -> i32 {
                if let Some((ip, host)) = sample.parse_dns_ringbuf_sample()
                    && let Ok(mut q) = queue_closure.lock()
                {
                    q.push((ip, host));
                }
                0
            })
            .ok()?;

        let ringbuf = builder.build().ok()?;

        Some(Self {
            _map: map,
            ringbuf,
            queue,
        })
    }

    fn poll_and_emit(&mut self, bus: &Bus) -> Result<(), String> {
        self.ringbuf
            .poll(Duration::from_millis(50))
            .map_err(|err| format!("ringbuf poll failed: {err}"))?;

        let mut queue = self
            .queue
            .lock()
            .map_err(|_| "ringbuf queue lock poisoned".to_string())?;

        for (ip, host) in queue.drain(..) {
            let _ = dispatch_kernel_event_with_backoff(
                &bus.kernel_tx,
                KernelEvent::DnsResolved { ip, host },
            );
        }

        Ok(())
    }
}

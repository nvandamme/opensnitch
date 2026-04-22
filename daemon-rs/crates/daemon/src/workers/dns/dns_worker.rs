use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use regex::Regex;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
    bus::Bus,
    models::dns_payload::DnsPayload,
    models::kernel_event::KernelEvent,
    services::dns::normalize_dns_host as normalize_dns_host_value,
    utils::{
        command_path::resolve_command_path,
        systemd_notify::{NotifyState, notify},
        name_parsing::case_folded,
    },
    workers::{
        KernelEventDispatch,
        runtime::control::{
            WorkerCommandResult, impl_restartable_thread_worker_control,
        },
    },
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CHILD_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const RESOLVED_VARLINK_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";
const RESOLVED_VARLINK_METHOD: &str = "io.systemd.Resolve.Monitor.SubscribeQueryResults";
pub(crate) fn decode_dns_monitor_state_label(state: u8) -> &'static str {
    match state {
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

fn set_monitor_state(monitor_state: &std::sync::atomic::AtomicU8, state: u8) {
    use std::sync::atomic::Ordering;
    let previous = monitor_state.swap(state, Ordering::Relaxed);
    if previous == state {
        return;
    }
    let label = decode_dns_monitor_state_label(state);
    notify(NotifyState::Status(&format!("DNS monitor state: {label}")));
}

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

struct DnsWorkerRuntime {
    shutdown: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

pub struct DnsWorkerControl {
    bus: Bus,
    daemon_shutdown: CancellationToken,
    runtime: Mutex<DnsWorkerRuntime>,
    monitor_state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl DnsWorkerControl {
    pub fn new(
        bus: Bus,
        daemon_shutdown: CancellationToken,
        monitor_state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    ) -> Self {
        let worker_shutdown = daemon_shutdown.child_token();
        let handle = Self::spawn_worker_thread(bus.clone(), worker_shutdown.clone(), monitor_state.clone());
        Self {
            bus,
            daemon_shutdown,
            runtime: Mutex::new(DnsWorkerRuntime {
                shutdown: worker_shutdown,
                handle: Some(handle),
            }),
            monitor_state,
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
                self.monitor_state.clone(),
            ));
        }

        WorkerCommandResult::Applied
    }

    fn spawn_worker_thread(
        bus: Bus,
        shutdown: CancellationToken,
        monitor_state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let monitor_shutdown = shutdown.clone();
            let monitor_bus = bus.clone();
            let monitor_state_clone = monitor_state.clone();
            let monitor_handle = thread::spawn(move || {
                Self::run_systemd_resolved_monitor(monitor_bus, monitor_shutdown, monitor_state_clone);
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

                            let mut fields = trimmed.split_whitespace();
                            let Some(ip) = fields.next() else {
                                continue;
                            };

                            let ip = ip.to_string();
                            let mut has_host = false;
                            for host in fields {
                                if host.starts_with('#') {
                                    break;
                                }
                                let Some(host) = Self::normalize_dns_host(host) else {
                                    continue;
                                };
                                has_host = true;
                                let Ok(addr) = ip.parse() else {
                                    continue;
                                };
                                let event =
                                    KernelEvent::DnsUpdate(DnsPayload::answer(host, addr));
                                if matches!(
                                    crate::workers::dispatch_kernel_event_with_backoff(
                                        &bus.kernel_tx,
                                        event
                                    ),
                                    KernelEventDispatch::ChannelClosed
                                ) {
                                    debug!("dns worker stopping: kernel channel closed");
                                    return;
                                }
                            }
                            if !has_host {
                                continue;
                            }
                        }
                    }
                }

                if crate::workers::sleep_with_shutdown(
                    &shutdown,
                    Duration::from_secs(30),
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
            }

            crate::workers::join_thread_with_timeout(
                "dns-systemd-monitor",
                monitor_handle,
                CHILD_JOIN_TIMEOUT,
                SHUTDOWN_POLL_INTERVAL,
            );
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_extract_dns_events_from_varlink(value: &Value) -> Vec<DnsPayload> {
        Self::extract_dns_events_from_varlink(value)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_decode_varlink_ip(bytes: &[Value]) -> Option<std::net::IpAddr> {
        Self::decode_varlink_ip(bytes)
    }

    fn normalize_dns_host(raw: &str) -> Option<String> {
        normalize_dns_host_value(raw)
    }
}

impl_restartable_thread_worker_control!(DnsWorkerControl, "dns");

impl DnsWorkerControl {
    fn run_systemd_resolved_monitor(
        bus: Bus,
        shutdown: CancellationToken,
        monitor_state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    ) {
        set_monitor_state(&monitor_state, DNS_MONITOR_STATE_IDLE);
        while !shutdown.is_cancelled() {
            if Path::new(RESOLVED_VARLINK_SOCKET).exists() {
                set_monitor_state(&monitor_state, DNS_MONITOR_STATE_VARLINK_CONNECTING);
                debug!(
                    socket = RESOLVED_VARLINK_SOCKET,
                    "[DNS] using systemd-resolved varlink monitor"
                );
                match Self::run_systemd_resolved_varlink_session(&bus, &shutdown, &monitor_state) {
                    Ok(()) => {}
                    Err(err) => {
                        set_monitor_state(&monitor_state, DNS_MONITOR_STATE_VARLINK_ERROR);
                        warn!("dns worker: systemd-resolved varlink monitor failed: {err}");
                    }
                }
            }

            if shutdown.is_cancelled() {
                break;
            }

            if resolve_command_path("resolvectl").is_some() {
                set_monitor_state(&monitor_state, DNS_MONITOR_STATE_FALLBACK_RESOLVECTL);
                debug!("[DNS] using resolvectl monitor fallback");
                Self::run_resolvectl_monitor_session(&bus, &shutdown, &monitor_state);
            }

            if crate::workers::sleep_with_shutdown(
                &shutdown,
                Duration::from_secs(2),
                SHUTDOWN_POLL_INTERVAL,
            ) {
                break;
            }
        }
        set_monitor_state(&monitor_state, DNS_MONITOR_STATE_STOPPED);
    }

    fn run_systemd_resolved_varlink_session(
        bus: &Bus,
        shutdown: &CancellationToken,
        monitor_state: &std::sync::atomic::AtomicU8,
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
        set_monitor_state(monitor_state, DNS_MONITOR_STATE_VARLINK_SUBSCRIBED);
        info!("[DNS] subscribed to systemd-resolved monitor events");

        let mut buf = vec![0_u8; 8192];
        let mut pending: Vec<u8> = Vec::with_capacity(8192);

        while !shutdown.is_cancelled() {
            match stream.read(&mut buf) {
                Ok(0) => {
                    set_monitor_state(monitor_state, DNS_MONITOR_STATE_VARLINK_DISCONNECTED);
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
                            Self::parse_and_emit_resolved_varlink_message(bus, &value);
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(err) if err.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(err) => return Err(format!("varlink read failed: {err}")),
            }
        }

        if shutdown.is_cancelled() {
            set_monitor_state(monitor_state, DNS_MONITOR_STATE_STOPPED);
            info!("[DNS] systemd-resolved monitor stopped");
        }

        Ok(())
    }

    fn parse_and_emit_resolved_varlink_message(bus: &Bus, value: &Value) {
        for event in Self::extract_dns_events_from_varlink(value) {
            match &event {
                DnsPayload::Answers(record) => {
                    trace!(host = %record.host, addresses = ?record.addresses, "[DNS] systemd-resolved answer event");
                }
                DnsPayload::Alias { alias, host } => {
                    trace!(alias = %alias, host = %host, "[DNS] systemd-resolved alias event");
                }
                DnsPayload::NxDomain { host, error_code } => {
                    trace!(host = %host, error_code = %error_code, "[DNS] systemd-resolved resolution failed");
                }
            }
            let _ = crate::workers::dispatch_kernel_event_with_backoff(
                &bus.kernel_tx,
                KernelEvent::DnsUpdate(event),
            );
        }
    }

    fn extract_dns_events_from_varlink(value: &Value) -> Vec<DnsPayload> {
        let payload = value.get("parameters").unwrap_or(value);

        // Match Go systemd-resolved path: only accept successful responses.
        let is_success = payload
            .get("state")
            .and_then(Value::as_str)
            .is_some_and(|state| case_folded(state) == RESOLVED_STATE_SUCCESS);
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
                .and_then(Self::normalize_dns_host);

            if let Some(address_bytes) = rr.get("address").and_then(Value::as_array) {
                let ip = Self::decode_varlink_ip(address_bytes);
                if let (Some(ip), Some(host)) = (ip, key_name) {
                    events.push(DnsPayload::answer(host, ip));
                }
                continue;
            }

            let cname = rr
                .get("name")
                .and_then(Value::as_str)
                .and_then(Self::normalize_dns_host);

            if let (Some(alias), Some(canonical)) = (key_name, cname) {
                events.push(DnsPayload::alias(alias, canonical));
            }
        }

        events
    }

    fn decode_varlink_ip(bytes: &[Value]) -> Option<std::net::IpAddr> {
        let parsed = bytes
            .iter()
            .map(|value| value.as_u64().and_then(|num| u8::try_from(num).ok()))
            .collect::<Option<Vec<u8>>>()?;

        match parsed.len() {
            4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                parsed[0], parsed[1], parsed[2], parsed[3],
            ))),
            16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&parsed);
                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }

    fn run_resolvectl_monitor_session(
        bus: &Bus,
        shutdown: &CancellationToken,
        monitor_state: &std::sync::atomic::AtomicU8,
    ) {
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
                if let (Some(host), Some(ip)) = (host, ip)
                    && let Some(host) = Self::normalize_dns_host(host)
                {
                    trace!(ip, host, "[DNS] resolvectl A/AAAA event");
                    let Ok(addr) = ip.parse() else {
                        continue;
                    };
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::DnsUpdate(DnsPayload::answer(host, addr)),
                    );
                }
                continue;
            }

            if let Some(re) = &re_cname
                && let Some(caps) = re.captures(&line)
            {
                let alias = caps.get(1).map(|m| m.as_str().trim_end_matches('.'));
                let canonical = caps.get(2).map(|m| m.as_str().trim_end_matches('.'));
                if let (Some(alias), Some(canonical)) = (alias, canonical)
                    && let Some(alias) = Self::normalize_dns_host(alias)
                    && let Some(canonical) = Self::normalize_dns_host(canonical)
                {
                    trace!(alias, canonical, "[DNS] resolvectl CNAME event");
                    let _ = crate::workers::dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::DnsUpdate(DnsPayload::alias(alias, canonical)),
                    );
                }
            }
        }

        let _ = child.kill();
        let _ = child.wait();
        if shutdown.is_cancelled() {
            set_monitor_state(monitor_state, DNS_MONITOR_STATE_STOPPED);
            info!("[DNS] resolvectl monitor stopped");
        } else {
            set_monitor_state(monitor_state, DNS_MONITOR_STATE_FALLBACK_DISCONNECTED);
            debug!("[DNS] resolvectl monitor disconnected");
        }
    }
}

use std::{
    collections::HashMap,
    ffi::c_void,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    os::raw::{c_char, c_int},
    ptr,
    sync::{Condvar, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use nix::libc;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::BorrowedFd,
    io::Errno,
    net::{RecvFlags, recv},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    adapters::socket_diag,
    bus::Bus,
    config::DefaultAction,
    models::{
        connection_state::{ConnectionAttempt, TransportProtocol},
        kernel_event::KernelEvent,
    },
};

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_QUEUE: u32 = 3;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_CFG_F_UID_GID: u32 = 1 << 3;

const DEFAULT_PACKET_SIZE: u32 = 4096;
const DEFAULT_QUEUE_SIZE: u32 = 4096;
const DEFAULT_SOCKET_RCVBUF_BYTES: i32 = 8 * 1024 * 1024;
const PRIMARY_DECISION_TIMEOUT: Duration = Duration::from_secs(1);
const REPEAT_DECISION_TIMEOUT: Duration = Duration::from_secs(120);
const REQUEUE_ALIAS_TTL: Duration = Duration::from_secs(5);

struct RuntimeState {
    bus: Bus,
    repeat_queue_num: u16,
    default_action: Mutex<DefaultAction>,
    uid_gid_support: Mutex<UidGidSupport>,
    decisions: Mutex<HashMap<u64, Option<Decision>>>,
    requeue_aliases: Mutex<HashMap<u64, RequeueAlias>>,
    cv: Condvar,
}

#[derive(Clone, Copy, Default)]
struct QueueMetrics {
    packets_total: u64,
    verdict_accept: u64,
    verdict_drop: u64,
    verdict_requeue: u64,
    recv_errors: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub struct QueueMetricsSnapshot {
    pub queue_num: u16,
    pub packets_total: u64,
    pub verdict_accept: u64,
    pub verdict_drop: u64,
    pub verdict_requeue: u64,
    pub recv_errors: u64,
}

#[derive(Clone, Copy)]
enum CapabilitySupport {
    Unknown,
    Supported,
    Unsupported,
}

struct UidGidSupport {
    uid: CapabilitySupport,
    gid: CapabilitySupport,
}

impl Default for UidGidSupport {
    fn default() -> Self {
        Self {
            uid: CapabilitySupport::Unknown,
            gid: CapabilitySupport::Unknown,
        }
    }
}

#[derive(Clone, Copy)]
struct Decision {
    allow: bool,
    reject: bool,
}

#[derive(Clone, Copy)]
struct RequeueAlias {
    request_id: u64,
    expires_at: Instant,
}

static RUNTIME: OnceLock<RuntimeState> = OnceLock::new();
static QUEUE_HANDLE_MAP: OnceLock<Mutex<HashMap<usize, u16>>> = OnceLock::new();
static QUEUE_METRICS: OnceLock<Mutex<HashMap<u16, QueueMetrics>>> = OnceLock::new();

fn queue_handle_map() -> &'static Mutex<HashMap<usize, u16>> {
    QUEUE_HANDLE_MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn queue_metrics_map() -> &'static Mutex<HashMap<u16, QueueMetrics>> {
    QUEUE_METRICS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[allow(dead_code)]
fn to_snapshot(queue_num: u16, metrics: QueueMetrics) -> QueueMetricsSnapshot {
    QueueMetricsSnapshot {
        queue_num,
        packets_total: metrics.packets_total,
        verdict_accept: metrics.verdict_accept,
        verdict_drop: metrics.verdict_drop,
        verdict_requeue: metrics.verdict_requeue,
        recv_errors: metrics.recv_errors,
    }
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
pub fn debug_metrics_snapshot() -> Vec<QueueMetricsSnapshot> {
    let Ok(metrics_map) = queue_metrics_map().lock() else {
        return Vec::new();
    };

    let mut out: Vec<_> = metrics_map
        .iter()
        .map(|(queue_num, metrics)| to_snapshot(*queue_num, *metrics))
        .collect();
    out.sort_by_key(|item| item.queue_num);
    out
}

fn record_packet_verdict(queue_num: u16, verdict: &PacketVerdict) {
    let Ok(mut metrics_map) = queue_metrics_map().lock() else {
        return;
    };
    let entry = metrics_map.entry(queue_num).or_default();
    entry.packets_total = entry.packets_total.saturating_add(1);

    match verdict {
        PacketVerdict::Accept { .. } => {
            entry.verdict_accept = entry.verdict_accept.saturating_add(1);
        }
        PacketVerdict::AcceptWithPacket { .. } => {
            entry.verdict_accept = entry.verdict_accept.saturating_add(1);
        }
        PacketVerdict::Drop => {
            entry.verdict_drop = entry.verdict_drop.saturating_add(1);
        }
        PacketVerdict::Requeue { .. } => {
            entry.verdict_requeue = entry.verdict_requeue.saturating_add(1);
        }
    }
}

fn record_recv_error(queue_num: u16) {
    let Ok(mut metrics_map) = queue_metrics_map().lock() else {
        return;
    };
    let entry = metrics_map.entry(queue_num).or_default();
    entry.recv_errors = entry.recv_errors.saturating_add(1);
}

#[cfg(test)]
fn reset_queue_metrics_for_test() {
    if let Ok(mut metrics_map) = queue_metrics_map().lock() {
        metrics_map.clear();
    }
}

#[cfg(test)]
fn queue_metrics_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("queue metrics test mutex poisoned")
}

#[cfg(test)]
fn queue_metrics_snapshot_for_test(queue_num: u16) -> QueueMetricsSnapshot {
    queue_metrics_map()
        .lock()
        .ok()
        .and_then(|metrics_map| {
            metrics_map
                .get(&queue_num)
                .copied()
                .map(|m| to_snapshot(queue_num, m))
        })
        .unwrap_or_else(|| QueueMetricsSnapshot {
            queue_num,
            ..QueueMetricsSnapshot::default()
        })
}

fn maybe_log_queue_metrics(queue_num: u16, last_log: &mut Instant) {
    if last_log.elapsed() < Duration::from_secs(60) {
        return;
    }
    *last_log = Instant::now();

    let Ok(metrics_map) = queue_metrics_map().lock() else {
        return;
    };
    let Some(metrics) = metrics_map.get(&queue_num).copied() else {
        return;
    };

    debug!(
        queue_num,
        packets_total = metrics.packets_total,
        verdict_accept = metrics.verdict_accept,
        verdict_drop = metrics.verdict_drop,
        verdict_requeue = metrics.verdict_requeue,
        recv_errors = metrics.recv_errors,
        "nfqueue queue metrics"
    );
}

pub fn init(bus: Bus, primary_queue_num: u16, default_action: DefaultAction) {
    let _ = RUNTIME.set(RuntimeState {
        bus,
        repeat_queue_num: primary_queue_num.saturating_add(1),
        default_action: Mutex::new(default_action),
        uid_gid_support: Mutex::new(UidGidSupport::default()),
        decisions: Mutex::new(HashMap::new()),
        requeue_aliases: Mutex::new(HashMap::new()),
        cv: Condvar::new(),
    });
}

pub fn set_default_action(action: DefaultAction) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };

    if let Ok(mut guard) = runtime.default_action.lock() {
        *guard = action;
    }
}

pub fn submit_verdict(request_id: u64, allow: bool, reject: bool) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };

    let mut guard = runtime
        .decisions
        .lock()
        .expect("nfqueue decision mutex poisoned");
    if !store_decision_if_pending(&mut guard, request_id, Decision { allow, reject }) {
        debug!(
            request_id,
            "ignoring late verdict reply for non-pending request"
        );
        return;
    }
    runtime.cv.notify_all();
}

fn store_decision_if_pending(
    decisions: &mut HashMap<u64, Option<Decision>>,
    request_id: u64,
    decision: Decision,
) -> bool {
    let Some(slot) = decisions.get_mut(&request_id) else {
        return false;
    };
    *slot = Some(decision);
    true
}

pub fn run(queue_num: u16, shutdown: CancellationToken) -> Result<()> {
    debug!(queue_num, backend = "ffi", "starting nfqueue backend");
    let q = QueueRuntime::open(queue_num)?;
    q.run(shutdown)
}

struct QueueRuntime {
    h: *mut nfq_handle,
    qh: *mut nfq_q_handle,
    fd: c_int,
    queue_num: u16,
}

impl QueueRuntime {
    fn open(queue_num: u16) -> Result<Self> {
        // SAFETY: nfqueue C API pointers are checked for null / return values.
        unsafe {
            let h = nfq_open();
            if h.is_null() {
                bail!("nfq_open failed");
            }

            let _ = nfq_unbind_pf(h, libc::AF_INET as u16);
            let _ = nfq_unbind_pf(h, libc::AF_INET6 as u16);

            if nfq_bind_pf(h, libc::AF_INET as u16) < 0 {
                let _ = nfq_close(h);
                bail!("nfq_bind_pf(AF_INET) failed");
            }
            if nfq_bind_pf(h, libc::AF_INET6 as u16) < 0 {
                let _ = nfq_close(h);
                bail!("nfq_bind_pf(AF_INET6) failed");
            }

            let qh = nfq_create_queue(h, queue_num, Some(nfqueue_callback), ptr::null_mut());
            if qh.is_null() {
                let _ = nfq_close(h);
                bail!("nfq_create_queue failed for queue {queue_num}");
            }

            let flags_rc = nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID);
            if flags_rc < 0 {
                debug!(
                    queue_num,
                    "nfqueue uid/gid metadata flags unavailable; continuing without queue flags"
                );
            }

            if let Ok(mut m) = queue_handle_map().lock() {
                m.insert(qh as usize, queue_num);
            }

            if nfq_set_queue_maxlen(qh, DEFAULT_QUEUE_SIZE) < 0 {
                let _ = nfq_destroy_queue(qh);
                let _ = nfq_close(h);
                bail!("nfq_set_queue_maxlen failed");
            }

            if nfq_set_mode(qh, NFQNL_COPY_PACKET, DEFAULT_PACKET_SIZE) < 0 {
                let _ = nfq_destroy_queue(qh);
                let _ = nfq_close(h);
                bail!("nfq_set_mode COPY_PACKET failed");
            }

            let fd = nfq_fd(h);
            if fd < 0 {
                let _ = nfq_destroy_queue(qh);
                let _ = nfq_close(h);
                bail!("nfq_fd failed");
            }

            tune_netlink_no_enobufs(fd);
            tune_socket_recv_buffer(fd, DEFAULT_SOCKET_RCVBUF_BYTES);

            Ok(Self {
                h,
                qh,
                fd,
                queue_num,
            })
        }
    }

    fn run(self, shutdown: CancellationToken) -> Result<()> {
        let mut buf = vec![0_u8; (DEFAULT_PACKET_SIZE * 2) as usize];
        let mut last_metrics_log = Instant::now();
        // SAFETY: self.fd comes from nfq_fd and remains valid for the lifetime of this loop.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let timeout = Timespec::try_from(Duration::from_millis(500)).ok();

        while !shutdown.is_cancelled() {
            maybe_log_queue_metrics(self.queue_num, &mut last_metrics_log);

            let mut pfd = [PollFd::new(&borrowed_fd, PollFlags::IN)];
            let poll_rc = poll(&mut pfd, timeout.as_ref()).context("poll nfqueue fd")?;
            if poll_rc == 0 {
                continue;
            }

            let flags = pfd[0].revents();
            if !flags.contains(PollFlags::IN) {
                continue;
            }

            let recv_rc = match recv(borrowed_fd, &mut buf, RecvFlags::DONTWAIT) {
                Ok((bytes_read, _recv_total_len)) => bytes_read,
                Err(err) => {
                    if err != Errno::WOULDBLOCK && err != Errno::AGAIN {
                        let io_err = io::Error::from_raw_os_error(err.raw_os_error());
                        record_recv_error(self.queue_num);
                        if err == Errno::NOBUFS {
                            debug!("nfqueue recv overflow (ENOBUFS): {io_err}");
                        } else {
                            warn!("nfqueue recv failed: {io_err}");
                        }
                    }
                    continue;
                }
            };
            if recv_rc == 0 {
                record_recv_error(self.queue_num);
                warn!("nfqueue recv returned EOF");
                continue;
            }

            if recv_rc > c_int::MAX as usize {
                record_recv_error(self.queue_num);
                warn!("nfqueue recv size overflow: {}", recv_rc);
                continue;
            }

            // SAFETY: recv_rc bytes were written into buf by recv.
            let handle_rc = unsafe {
                nfq_handle_packet(self.h, buf.as_mut_ptr().cast::<c_char>(), recv_rc as c_int)
            };
            if handle_rc < 0 {
                let io_err = io::Error::last_os_error();
                let errno = io_err.raw_os_error().unwrap_or_default();
                if errno == libc::ENOBUFS || errno == libc::EAGAIN || errno == libc::EINTR {
                    debug!(rc = handle_rc, errno, "nfq_handle_packet transient failure");
                } else {
                    warn!(rc = handle_rc, errno, "nfq_handle_packet failed");
                }
            }
        }

        Ok(())
    }
}

fn tune_socket_recv_buffer(fd: c_int, size: i32) {
    // SAFETY: setsockopt is called with a valid nfqueue fd and a properly sized integer buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const i32).cast::<c_void>(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        warn!(
            requested_bytes = size,
            err = %err,
            "nfqueue socket recv buffer tuning failed"
        );
    }
}

fn tune_netlink_no_enobufs(fd: c_int) {
    let value: i32 = 1;
    // SAFETY: setsockopt is called with a valid nfqueue netlink fd and integer option payload.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_NETLINK,
            libc::NETLINK_NO_ENOBUFS,
            (&value as *const i32).cast::<c_void>(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        debug!(err = %err, "nfqueue netlink no_enobufs tuning not applied");
    }
}

impl Drop for QueueRuntime {
    fn drop(&mut self) {
        // SAFETY: pointers are created by libnetfilter_queue and may be null.
        unsafe {
            if !self.qh.is_null() {
                if let Ok(mut m) = queue_handle_map().lock() {
                    m.remove(&(self.qh as usize));
                }
                let _ = nfq_destroy_queue(self.qh);
                self.qh = ptr::null_mut();
            }
            if !self.h.is_null() {
                let _ = nfq_close(self.h);
                self.h = ptr::null_mut();
            }
        }
    }
}

#[derive(Clone)]
enum PacketVerdict {
    Accept {
        mark: u32,
    },
    #[allow(dead_code)]
    AcceptWithPacket {
        mark: u32,
        packet: Vec<u8>,
    },
    Drop,
    Requeue {
        queue_num: u16,
        mark: u32,
    },
}

fn default_action_verdict(action: DefaultAction, mark: u32) -> PacketVerdict {
    default_action_verdict_for_attempt(action, mark, None)
}

fn default_action_verdict_for_attempt(
    action: DefaultAction,
    mark: u32,
    attempt: Option<&ConnectionAttempt>,
) -> PacketVerdict {
    if action.allows() {
        PacketVerdict::Accept { mark }
    } else {
        if action.rejects()
            && let Some(attempt) = attempt
        {
            reject_socket_for_attempt(attempt);
        }
        PacketVerdict::Drop
    }
}

fn timeout_fallback_verdict(
    queue_num: u16,
    repeat_queue_num: Option<u16>,
    default_action: DefaultAction,
    mark: u32,
    attempt: Option<&ConnectionAttempt>,
) -> PacketVerdict {
    if let Some(repeat_queue_num) = repeat_queue_num
        && queue_num != repeat_queue_num
    {
        warn!(
            queue_num,
            repeat_queue_num,
            fallback_reason = "timeout",
            fallback_mode = "requeue",
            "nfqueue overload fallback requeue"
        );
        return PacketVerdict::Requeue {
            queue_num: repeat_queue_num,
            mark,
        };
    }

    let verdict = default_action_verdict_for_attempt(default_action, mark, attempt);

    let verdict_name = match verdict {
        PacketVerdict::Accept { .. } => "accept",
        PacketVerdict::AcceptWithPacket { .. } => "accept-with-packet",
        PacketVerdict::Drop => "drop",
        PacketVerdict::Requeue { .. } => "requeue",
    };

    warn!(
        queue_num,
        fallback_reason = "timeout",
        fallback_mode = "default-action",
        default_action = ?default_action,
        verdict = verdict_name,
        "nfqueue overload fallback final verdict"
    );

    verdict
}

fn packet_verdict_to_c(verdict: &PacketVerdict) -> (u32, u32) {
    match verdict {
        PacketVerdict::Accept { mark } => (NF_ACCEPT, *mark),
        PacketVerdict::AcceptWithPacket { mark, .. } => (NF_ACCEPT, *mark),
        PacketVerdict::Drop => (NF_DROP, 0),
        PacketVerdict::Requeue { queue_num, mark } => {
            (NF_QUEUE | ((*queue_num as u32) << 16), *mark)
        }
    }
}

fn packet_verdict_payload(verdict: &PacketVerdict) -> Option<&[u8]> {
    match verdict {
        PacketVerdict::AcceptWithPacket { packet, .. } if !packet.is_empty() => Some(packet),
        _ => None,
    }
}

fn compute_packet_verdict(
    queue_num: u16,
    packet_id: u32,
    payload: &[u8],
    uid: u32,
    mark: u32,
    iface_in_idx: u32,
    iface_out_idx: u32,
) -> PacketVerdict {
    let dns_answers = parse_dns_answer_mappings(payload);
    let is_dns_response = !dns_answers.is_empty();

    if let Some(runtime) = RUNTIME.get() {
        for (ip, host) in dns_answers {
            let _ = runtime
                .bus
                .kernel_tx
                .try_send(KernelEvent::DnsResolved { ip, host });
        }
    }

    if is_dns_response {
        return PacketVerdict::Accept { mark };
    }

    let payload_signature = packet_signature(payload, uid, mark);
    let repeat_queue_num = RUNTIME.get().map(|runtime| runtime.repeat_queue_num);
    let request_id = resolve_request_id(queue_num, packet_id, payload_signature, repeat_queue_num);

    if let Some(mut attempt) =
        parse_connection_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx)
    {
        if attempt.dst_port == 53 {
            attempt.dns_query = parse_dns_questions(payload).into_iter().last();
        }

        if let Some(runtime) = RUNTIME.get() {
            if !enqueue_connect_attempt_non_blocking(&runtime.bus, attempt.clone()) {
                debug!(
                    request_id,
                    queue_num, "kernel event queue saturated, applying timeout fallback verdict"
                );
                let action = runtime
                    .default_action
                    .lock()
                    .ok()
                    .map(|g| *g)
                    .unwrap_or(DefaultAction::Allow);
                return timeout_fallback_verdict(
                    queue_num,
                    repeat_queue_num,
                    action,
                    mark,
                    Some(&attempt),
                );
            }
        }

        let decision_timeout = decision_timeout_for_queue(queue_num, repeat_queue_num);
        let keep_pending_on_timeout = should_keep_pending_on_timeout(queue_num, repeat_queue_num);

        let decision =
            match wait_for_decision(request_id, decision_timeout, keep_pending_on_timeout) {
                Some(decision) => decision,
                None => {
                    let action = RUNTIME
                        .get()
                        .and_then(|runtime| runtime.default_action.lock().ok().map(|g| *g))
                        .unwrap_or(DefaultAction::Allow);

                    if keep_pending_on_timeout {
                        remember_requeue_alias(payload_signature, request_id);
                    }

                    return timeout_fallback_verdict(
                        queue_num,
                        repeat_queue_num,
                        action,
                        mark,
                        Some(&attempt),
                    );
                }
            };

        if !decision.allow && decision.reject {
            reject_socket_for_attempt(&attempt);
        }

        return if decision.allow {
            PacketVerdict::Accept { mark }
        } else {
            PacketVerdict::Drop
        };
    }

    let action = RUNTIME
        .get()
        .and_then(|runtime| runtime.default_action.lock().ok().map(|g| *g))
        .unwrap_or(DefaultAction::Allow);
    default_action_verdict(action, mark)
}

fn reject_socket_for_attempt(attempt: &ConnectionAttempt) {
    let family = infer_family(attempt);
    if let (Some(src), Some(dst)) = (attempt.src_ip.parse().ok(), attempt.dst_ip.parse().ok()) {
        if let Some(ipproto) = protocol_to_ipproto(attempt.protocol)
            && let Ok(Some(sock)) = socket_diag::find_socket(
                family,
                ipproto,
                src,
                attempt.src_port,
                dst,
                attempt.dst_port,
            )
        {
            let _ = socket_diag::kill_socket(family, ipproto, &sock);
        }
    }
}

fn enqueue_connect_attempt_non_blocking(bus: &Bus, attempt: ConnectionAttempt) -> bool {
    bus.connect_tx.try_send(attempt).is_ok()
}

unsafe extern "C" fn nfqueue_callback(
    qh: *mut nfq_q_handle,
    _nfmsg: *mut nfgenmsg,
    nfa: *mut nfq_data,
    _data: *mut c_void,
) -> c_int {
    let queue_num = queue_handle_map()
        .lock()
        .ok()
        .and_then(|m| m.get(&(qh as usize)).copied())
        .unwrap_or(0);

    let header = unsafe { nfq_get_msg_packet_hdr(nfa) };
    if header.is_null() {
        return 0;
    }

    let packet_id = u32::from_be(unsafe { (*header).packet_id });

    let mut payload_ptr: *mut u8 = ptr::null_mut();
    let payload_len = unsafe { nfq_get_payload(nfa, &mut payload_ptr as *mut *mut u8) };
    let payload = if payload_len > 0 && !payload_ptr.is_null() {
        unsafe { std::slice::from_raw_parts(payload_ptr.cast::<u8>(), payload_len as usize) }
    } else {
        &[]
    };

    let (uid, _) = read_uid_gid(nfa);
    let mark = unsafe { nfq_get_nfmark(nfa) };

    let iface_in_idx = unsafe { nfq_get_indev(nfa) };
    let iface_out_idx = unsafe { nfq_get_outdev(nfa) };

    let packet_verdict = compute_packet_verdict(
        queue_num,
        packet_id,
        payload,
        uid,
        mark,
        iface_in_idx,
        iface_out_idx,
    );
    record_packet_verdict(queue_num, &packet_verdict);

    let (verdict, verdict_mark) = packet_verdict_to_c(&packet_verdict);
    let (data_len, data_ptr) = if let Some(packet) = packet_verdict_payload(&packet_verdict) {
        (packet.len() as u32, packet.as_ptr())
    } else {
        (0_u32, ptr::null())
    };

    unsafe { nfq_set_verdict2(qh, packet_id, verdict, verdict_mark, data_len, data_ptr) }
}

fn read_uid_gid(nfa: *mut nfq_data) -> (u32, u32) {
    let mut uid = 0_u32;
    let mut gid = 0_u32;

    let Some(runtime) = RUNTIME.get() else {
        unsafe {
            let _ = nfq_get_uid(nfa, &mut uid as *mut u32);
            let _ = nfq_get_gid(nfa, &mut gid as *mut u32);
        }
        return (uid, gid);
    };

    let mut caps = match runtime.uid_gid_support.lock() {
        Ok(guard) => guard,
        Err(_) => return (uid, gid),
    };

    if !matches!(caps.uid, CapabilitySupport::Unsupported) {
        let rc = unsafe { nfq_get_uid(nfa, &mut uid as *mut u32) };
        if rc >= 0 {
            caps.uid = CapabilitySupport::Supported;
        } else if matches!(caps.uid, CapabilitySupport::Unknown) {
            caps.uid = CapabilitySupport::Unsupported;
            warn!("nfqueue uid metadata unavailable; continuing without uid extraction");
        }
    }

    if !matches!(caps.gid, CapabilitySupport::Unsupported) {
        let rc = unsafe { nfq_get_gid(nfa, &mut gid as *mut u32) };
        if rc >= 0 {
            caps.gid = CapabilitySupport::Supported;
        } else if matches!(caps.gid, CapabilitySupport::Unknown) {
            caps.gid = CapabilitySupport::Unsupported;
            warn!("nfqueue gid metadata unavailable; continuing without gid extraction");
        }
    }

    (uid, gid)
}

fn infer_family(attempt: &ConnectionAttempt) -> u8 {
    if attempt.src_ip.contains(':') {
        libc::AF_INET6 as u8
    } else {
        libc::AF_INET as u8
    }
}

fn protocol_to_ipproto(protocol: TransportProtocol) -> Option<u8> {
    match protocol {
        TransportProtocol::Tcp => Some(libc::IPPROTO_TCP as u8),
        TransportProtocol::Udp => Some(libc::IPPROTO_UDP as u8),
        TransportProtocol::UdpLite => Some(136_u8),
        TransportProtocol::Sctp => Some(132_u8),
        TransportProtocol::Icmp => None,
    }
}

fn parse_dns_answer_mappings(payload: &[u8]) -> Vec<(String, String)> {
    let Some((udp_offset, src_port, _dst_port)) = udp_offsets(payload) else {
        return Vec::new();
    };
    if src_port != 53 {
        return Vec::new();
    }
    if payload.len() < udp_offset + 8 {
        return Vec::new();
    }

    let dns = &payload[udp_offset + 8..];
    if dns.len() < 12 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([dns[4], dns[5]]) as usize;
    let ancount = u16::from_be_bytes([dns[6], dns[7]]) as usize;
    let mut pos = 12_usize;

    let mut question_name = String::new();
    for _ in 0..qdcount {
        let Some((name, next)) = parse_dns_name(dns, pos) else {
            return Vec::new();
        };
        question_name = name;
        if dns.len() < next + 4 {
            return Vec::new();
        }
        pos = next + 4;
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        let Some((answer_name, next)) = parse_dns_name(dns, pos) else {
            break;
        };
        if dns.len() < next + 10 {
            break;
        }
        let rtype = u16::from_be_bytes([dns[next], dns[next + 1]]);
        let rdlen = u16::from_be_bytes([dns[next + 8], dns[next + 9]]) as usize;
        let rdata_off = next + 10;
        if dns.len() < rdata_off + rdlen {
            break;
        }

        match rtype {
            1 if rdlen == 4 => {
                let ip = Ipv4Addr::new(
                    dns[rdata_off],
                    dns[rdata_off + 1],
                    dns[rdata_off + 2],
                    dns[rdata_off + 3],
                );
                if !question_name.is_empty() {
                    out.push((ip.to_string(), question_name.clone()));
                }
            }
            28 if rdlen == 16 => {
                if let Ok(octets) = <[u8; 16]>::try_from(&dns[rdata_off..rdata_off + 16]) {
                    if !question_name.is_empty() {
                        out.push((Ipv6Addr::from(octets).to_string(), question_name.clone()));
                    }
                }
            }
            5 => {
                if let Some((cname, _)) = parse_dns_name(dns, rdata_off)
                    && !answer_name.is_empty()
                    && !cname.is_empty()
                {
                    // Mirror Go behavior: canonical -> alias mapping.
                    out.push((cname, answer_name));
                }
            }
            _ => {}
        }

        pos = rdata_off + rdlen;
    }

    out
}

fn parse_dns_questions(payload: &[u8]) -> Vec<String> {
    if let Some((udp_offset, _src_port, dst_port)) = udp_offsets(payload) {
        if dst_port == 53 && payload.len() >= udp_offset + 8 {
            return parse_dns_question_names(&payload[udp_offset + 8..]);
        }
    }

    if let Some((tcp_offset, _src_port, dst_port, tcp_header_len)) = tcp_offsets(payload) {
        if dst_port == 53 {
            let dns_off = tcp_offset + tcp_header_len;
            if payload.len() >= dns_off + 2 {
                let declared_len =
                    u16::from_be_bytes([payload[dns_off], payload[dns_off + 1]]) as usize;
                let dns_start = dns_off + 2;
                let dns_end = dns_start.saturating_add(declared_len).min(payload.len());
                if dns_end > dns_start {
                    return parse_dns_question_names(&payload[dns_start..dns_end]);
                }
            }
        }
    }

    Vec::new()
}

fn parse_dns_question_names(dns: &[u8]) -> Vec<String> {
    if dns.len() < 12 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([dns[4], dns[5]]) as usize;
    let mut pos = 12_usize;
    let mut out = Vec::new();

    for _ in 0..qdcount {
        let Some((name, next)) = parse_dns_name(dns, pos) else {
            break;
        };
        if dns.len() < next + 4 {
            break;
        }
        if !name.is_empty() {
            out.push(name);
        }
        pos = next + 4;
    }

    out
}

fn tcp_offsets(payload: &[u8]) -> Option<(usize, u16, u16, usize)> {
    if payload.is_empty() {
        return None;
    }

    let version = payload[0] >> 4;
    match version {
        4 => {
            if payload.len() < 20 {
                return None;
            }
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            if payload.len() < ihl + 20 || payload[9] != 6 {
                return None;
            }

            let data_off = ((payload[ihl + 12] >> 4) as usize) * 4;
            if data_off < 20 || payload.len() < ihl + data_off {
                return None;
            }

            let src = u16::from_be_bytes([payload[ihl], payload[ihl + 1]]);
            let dst = u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]);
            Some((ihl, src, dst, data_off))
        }
        6 => {
            if payload.len() < 60 || payload[6] != 6 {
                return None;
            }
            let off = 40;

            let data_off = ((payload[off + 12] >> 4) as usize) * 4;
            if data_off < 20 || payload.len() < off + data_off {
                return None;
            }

            let src = u16::from_be_bytes([payload[off], payload[off + 1]]);
            let dst = u16::from_be_bytes([payload[off + 2], payload[off + 3]]);
            Some((off, src, dst, data_off))
        }
        _ => None,
    }
}

fn udp_offsets(payload: &[u8]) -> Option<(usize, u16, u16)> {
    if payload.is_empty() {
        return None;
    }
    let version = payload[0] >> 4;
    match version {
        4 => {
            if payload.len() < 20 {
                return None;
            }
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            if payload.len() < ihl + 4 || payload[9] != 17 {
                return None;
            }
            let src = u16::from_be_bytes([payload[ihl], payload[ihl + 1]]);
            let dst = u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]);
            Some((ihl, src, dst))
        }
        6 => {
            if payload.len() < 44 || payload[6] != 17 {
                return None;
            }
            let off = 40;
            let src = u16::from_be_bytes([payload[off], payload[off + 1]]);
            let dst = u16::from_be_bytes([payload[off + 2], payload[off + 3]]);
            Some((off, src, dst))
        }
        _ => None,
    }
}

fn parse_dns_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_return = 0;
    let mut depth = 0;

    loop {
        if pos >= buf.len() || depth > 32 {
            return None;
        }
        depth += 1;
        let len = buf[pos];
        if len == 0 {
            let next = if jumped { jump_return } else { pos + 1 };
            return Some((labels.join("."), next));
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len as u16 & 0x3F) << 8) | buf[pos + 1] as u16) as usize;
            if !jumped {
                jump_return = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }

        let l = len as usize;
        if pos + 1 + l > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[pos + 1..pos + 1 + l]).to_string());
        pos += 1 + l;
    }
}

fn wait_for_decision(
    request_id: u64,
    timeout: Duration,
    keep_pending_on_timeout: bool,
) -> Option<Decision> {
    let runtime = RUNTIME.get()?;
    let mut guard = runtime.decisions.lock().ok()?;
    guard.entry(request_id).or_insert(None);

    let deadline = Instant::now() + timeout;
    loop {
        if let Some(Some(value)) = guard.get(&request_id) {
            let out = *value;
            guard.remove(&request_id);
            return Some(out);
        }

        let now = Instant::now();
        if now >= deadline {
            if !keep_pending_on_timeout {
                guard.remove(&request_id);
            }
            debug!(
                request_id,
                "nfqueue verdict timeout, applying configured default action"
            );
            return None;
        }

        let remain = deadline.saturating_duration_since(now);
        let (g, _) = runtime.cv.wait_timeout(guard, remain).ok()?;
        guard = g;
    }
}

fn decision_timeout_for_queue(queue_num: u16, repeat_queue_num: Option<u16>) -> Duration {
    if Some(queue_num) == repeat_queue_num {
        REPEAT_DECISION_TIMEOUT
    } else {
        PRIMARY_DECISION_TIMEOUT
    }
}

fn should_keep_pending_on_timeout(queue_num: u16, repeat_queue_num: Option<u16>) -> bool {
    repeat_queue_num.is_some() && Some(queue_num) != repeat_queue_num
}

fn packet_signature(payload: &[u8], uid: u32, mark: u32) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for b in uid.to_le_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for b in mark.to_le_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for b in payload {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn resolve_request_id(
    queue_num: u16,
    packet_id: u32,
    payload_signature: u64,
    repeat_queue_num: Option<u16>,
) -> u64 {
    if Some(queue_num) == repeat_queue_num
        && let Some(request_id) = claim_requeue_alias(payload_signature)
    {
        return request_id;
    }

    ((queue_num as u64) << 32) | packet_id as u64
}

fn remember_requeue_alias(payload_signature: u64, request_id: u64) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };

    let mut aliases = match runtime.requeue_aliases.lock() {
        Ok(aliases) => aliases,
        Err(_) => return,
    };

    prune_requeue_aliases(&mut aliases);
    aliases.insert(
        payload_signature,
        RequeueAlias {
            request_id,
            expires_at: Instant::now() + REQUEUE_ALIAS_TTL,
        },
    );
}

fn claim_requeue_alias(payload_signature: u64) -> Option<u64> {
    let runtime = RUNTIME.get()?;
    let mut aliases = runtime.requeue_aliases.lock().ok()?;
    prune_requeue_aliases(&mut aliases);
    aliases
        .remove(&payload_signature)
        .map(|alias| alias.request_id)
}

fn prune_requeue_aliases(aliases: &mut HashMap<u64, RequeueAlias>) {
    let now = Instant::now();
    aliases.retain(|_, alias| alias.expires_at > now);
}

fn parse_connection_attempt(
    request_id: u64,
    payload: &[u8],
    uid: u32,
    iface_in_idx: u32,
    iface_out_idx: u32,
) -> Option<ConnectionAttempt> {
    if payload.is_empty() {
        return None;
    }

    let version = payload[0] >> 4;
    match version {
        4 => parse_ipv4_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx),
        6 => parse_ipv6_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx),
        _ => None,
    }
}

fn parse_ipv4_attempt(
    request_id: u64,
    payload: &[u8],
    uid: u32,
    iface_in_idx: u32,
    iface_out_idx: u32,
) -> Option<ConnectionAttempt> {
    if payload.len() < 20 {
        return None;
    }

    let ihl = ((payload[0] & 0x0f) as usize) * 4;
    if payload.len() < ihl + 4 {
        return None;
    }

    let protocol = match payload[9] {
        1 => TransportProtocol::Icmp,
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        132 => TransportProtocol::Sctp,
        136 => TransportProtocol::UdpLite,
        _ => return None,
    };

    let src_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]).to_string();
    let dst_ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]).to_string();

    let (src_port, dst_port) = match protocol {
        TransportProtocol::Icmp => (0, 0),
        _ => {
            if payload.len() < ihl + 4 {
                return None;
            }
            (
                u16::from_be_bytes([payload[ihl], payload[ihl + 1]]),
                u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]),
            )
        }
    };

    Some(ConnectionAttempt {
        request_id,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        iface_in_idx,
        iface_out_idx,
        dns_query: None,
        pid: 0,
        uid,
    })
}

fn parse_ipv6_attempt(
    request_id: u64,
    payload: &[u8],
    uid: u32,
    iface_in_idx: u32,
    iface_out_idx: u32,
) -> Option<ConnectionAttempt> {
    if payload.len() < 44 {
        return None;
    }

    let protocol = match payload[6] {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        58 => TransportProtocol::Icmp,
        132 => TransportProtocol::Sctp,
        136 => TransportProtocol::UdpLite,
        _ => return None,
    };

    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[8..24]).ok()?).to_string();
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[24..40]).ok()?).to_string();

    let (src_port, dst_port) = match protocol {
        TransportProtocol::Icmp => (0, 0),
        _ => {
            if payload.len() < 44 {
                return None;
            }
            (
                u16::from_be_bytes([payload[40], payload[41]]),
                u16::from_be_bytes([payload[42], payload[43]]),
            )
        }
    };

    Some(ConnectionAttempt {
        request_id,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        iface_in_idx,
        iface_out_idx,
        dns_query: None,
        pid: 0,
        uid,
    })
}

#[repr(C)]
struct nfq_handle {
    _private: [u8; 0],
}

#[repr(C)]
struct nfq_q_handle {
    _private: [u8; 0],
}

#[repr(C)]
struct nfgenmsg {
    _private: [u8; 0],
}

#[repr(C)]
struct nfq_data {
    _private: [u8; 0],
}

#[repr(C)]
struct nfqnl_msg_packet_hdr {
    packet_id: u32,
    hw_protocol: u16,
    hook: u8,
}

type NfqCallback =
    unsafe extern "C" fn(*mut nfq_q_handle, *mut nfgenmsg, *mut nfq_data, *mut c_void) -> c_int;

#[link(name = "netfilter_queue")]
unsafe extern "C" {
    fn nfq_open() -> *mut nfq_handle;
    fn nfq_close(h: *mut nfq_handle) -> c_int;
    fn nfq_unbind_pf(h: *mut nfq_handle, pf: u16) -> c_int;
    fn nfq_bind_pf(h: *mut nfq_handle, pf: u16) -> c_int;

    fn nfq_create_queue(
        h: *mut nfq_handle,
        num: u16,
        cb: Option<NfqCallback>,
        data: *mut c_void,
    ) -> *mut nfq_q_handle;
    fn nfq_destroy_queue(qh: *mut nfq_q_handle) -> c_int;

    fn nfq_set_mode(qh: *mut nfq_q_handle, mode: u8, range: u32) -> c_int;
    fn nfq_set_queue_maxlen(qh: *mut nfq_q_handle, queuelen: u32) -> c_int;
    fn nfq_set_queue_flags(qh: *mut nfq_q_handle, mask: u32, flags: u32) -> c_int;
    fn nfq_fd(h: *mut nfq_handle) -> c_int;

    fn nfq_handle_packet(h: *mut nfq_handle, buf: *mut c_char, len: c_int) -> c_int;
    fn nfq_get_msg_packet_hdr(tb: *mut nfq_data) -> *mut nfqnl_msg_packet_hdr;
    fn nfq_get_payload(tb: *mut nfq_data, data: *mut *mut u8) -> c_int;
    fn nfq_get_uid(tb: *mut nfq_data, uid: *mut u32) -> c_int;
    fn nfq_get_gid(tb: *mut nfq_data, gid: *mut u32) -> c_int;
    fn nfq_get_indev(tb: *mut nfq_data) -> u32;
    fn nfq_get_outdev(tb: *mut nfq_data) -> u32;
    fn nfq_get_nfmark(tb: *mut nfq_data) -> u32;

    fn nfq_set_verdict2(
        qh: *mut nfq_q_handle,
        id: u32,
        verdict: u32,
        mark: u32,
        datalen: u32,
        buf: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use crate::{
        bus::build_bus,
        config::DefaultAction,
        models::connection_state::{ConnectionAttempt, TransportProtocol},
    };

    use super::*;

    #[test]
    fn timeout_policy_uses_short_primary_and_long_repeat_budget() {
        assert_eq!(
            decision_timeout_for_queue(10, Some(11)),
            PRIMARY_DECISION_TIMEOUT
        );
        assert_eq!(
            decision_timeout_for_queue(11, Some(11)),
            REPEAT_DECISION_TIMEOUT
        );
        assert!(should_keep_pending_on_timeout(10, Some(11)));
        assert!(!should_keep_pending_on_timeout(11, Some(11)));
    }

    #[test]
    fn store_decision_updates_only_existing_pending_entries() {
        let mut decisions = HashMap::new();
        decisions.insert(7_u64, None);

        assert!(store_decision_if_pending(
            &mut decisions,
            7,
            Decision {
                allow: true,
                reject: false,
            }
        ));
        assert!(matches!(
            decisions.get(&7),
            Some(Some(Decision {
                allow: true,
                reject: false
            }))
        ));

        assert!(!store_decision_if_pending(
            &mut decisions,
            8,
            Decision {
                allow: false,
                reject: true,
            }
        ));
        assert!(!decisions.contains_key(&8));
    }

    #[test]
    fn packet_signature_is_stable_for_same_metadata() {
        let payload = [0xde_u8, 0xad, 0xbe, 0xef];
        let a = packet_signature(&payload, 1000, 42);
        let b = packet_signature(&payload, 1000, 42);
        let c = packet_signature(&payload, 1001, 42);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn prune_requeue_aliases_removes_expired_entries() {
        let mut aliases = HashMap::new();
        aliases.insert(
            1,
            RequeueAlias {
                request_id: 10,
                expires_at: Instant::now() - Duration::from_millis(1),
            },
        );
        aliases.insert(
            2,
            RequeueAlias {
                request_id: 11,
                expires_at: Instant::now() + Duration::from_secs(1),
            },
        );

        prune_requeue_aliases(&mut aliases);
        assert!(!aliases.contains_key(&1));
        assert_eq!(aliases.get(&2).map(|v| v.request_id), Some(11));
    }

    #[test]
    fn enqueue_connect_attempt_non_blocking_uses_dedicated_connect_queue() {
        let (bus, mut rx) = build_bus(1);
        let _ = bus.kernel_tx.try_send(KernelEvent::DnsResolved {
            ip: "127.0.0.1".to_string(),
            host: "localhost".to_string(),
        });

        let attempt = ConnectionAttempt {
            request_id: 1,
            protocol: TransportProtocol::Tcp,
            src_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 80,
            iface_in_idx: 0,
            iface_out_idx: 0,
            dns_query: None,
            pid: 1000,
            uid: 1000,
        };

        assert!(enqueue_connect_attempt_non_blocking(&bus, attempt));

        let _ = rx.connect_rx.try_recv();
        let _ = rx.kernel_rx.try_recv();
    }

    #[test]
    fn enqueue_connect_attempt_non_blocking_returns_false_when_connect_queue_is_full() {
        let (bus, mut rx) = build_bus(1);

        let attempt = ConnectionAttempt {
            request_id: 1,
            protocol: TransportProtocol::Tcp,
            src_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 80,
            iface_in_idx: 0,
            iface_out_idx: 0,
            dns_query: None,
            pid: 1000,
            uid: 1000,
        };

        assert!(enqueue_connect_attempt_non_blocking(&bus, attempt.clone()));
        assert!(!enqueue_connect_attempt_non_blocking(&bus, attempt));

        let _ = rx.connect_rx.try_recv();
    }

    fn runtime_test_guard() -> MutexGuard<'static, ()> {
        static RUNTIME_TEST_GUARD: Mutex<()> = Mutex::new(());
        RUNTIME_TEST_GUARD
            .lock()
            .expect("runtime test mutex poisoned")
    }

    fn build_ipv4_dns_response_payload() -> Vec<u8> {
        let mut dns = vec![
            0x12, 0x34, 0x81, 0x80, // id + flags(response)
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];

        // Question: example.com A IN
        dns.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // qtype A
            0x00, 0x01, // qclass IN
        ]);

        // Answer: name pointer to question, A record 93.184.216.34
        dns.extend_from_slice(&[
            0xC0, 0x0C, // pointer to question name
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x3C, // TTL 60s
            0x00, 0x04, // rdlength
            93, 184, 216, 34,
        ]);

        let udp_len = (8 + dns.len()) as u16;
        let ip_total_len = (20 + udp_len as usize) as u16;

        let mut payload = vec![0_u8; 20 + 8];
        payload[0] = 0x45; // IPv4, header len 20
        payload[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        payload[8] = 64; // ttl
        payload[9] = 17; // udp
        payload[12..16].copy_from_slice(&[8, 8, 8, 8]);
        payload[16..20].copy_from_slice(&[192, 0, 2, 10]);

        let udp_offset = 20;
        payload[udp_offset..udp_offset + 2].copy_from_slice(&53_u16.to_be_bytes());
        payload[udp_offset + 2..udp_offset + 4].copy_from_slice(&53000_u16.to_be_bytes());
        payload[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
        payload[udp_offset + 6..udp_offset + 8].copy_from_slice(&0_u16.to_be_bytes());

        payload.extend_from_slice(&dns);
        payload
    }

    #[test]
    fn dns_response_packet_fast_paths_to_accept_even_when_default_action_is_deny() {
        let _guard = runtime_test_guard();

        if RUNTIME.get().is_none() {
            let (bus, _rx) = build_bus(16);
            init(bus, 6000, DefaultAction::Deny);
        }
        set_default_action(DefaultAction::Deny);

        let payload = build_ipv4_dns_response_payload();
        let verdict = compute_packet_verdict(6000, 123, &payload, 1000, 0x5a, 0, 0);

        assert!(matches!(verdict, PacketVerdict::Accept { mark: 0x5a }));

        set_default_action(DefaultAction::Allow);
    }

    fn simulate_timeout_flow(
        primary_queue_num: u16,
        repeat_queue_num: u16,
        default_action: DefaultAction,
        mark: u32,
    ) -> (PacketVerdict, PacketVerdict) {
        let first = timeout_fallback_verdict(
            primary_queue_num,
            Some(repeat_queue_num),
            default_action,
            mark,
            None,
        );

        let second = match first {
            PacketVerdict::Requeue { queue_num, mark } => timeout_fallback_verdict(
                queue_num,
                Some(repeat_queue_num),
                default_action,
                mark,
                None,
            ),
            _ => first.clone(),
        };

        (first, second)
    }

    #[test]
    fn timeout_requeues_on_primary_queue_and_preserves_mark() {
        let verdict = timeout_fallback_verdict(10, Some(11), DefaultAction::Allow, 0x2a, None);
        match verdict {
            PacketVerdict::Requeue { queue_num, mark } => {
                assert_eq!(queue_num, 11);
                assert_eq!(mark, 0x2a);
            }
            _ => panic!("expected requeue verdict"),
        }
    }

    #[test]
    fn timeout_applies_default_action_on_repeat_queue() {
        let allow_verdict =
            timeout_fallback_verdict(11, Some(11), DefaultAction::Allow, 0x99, None);
        assert!(matches!(
            allow_verdict,
            PacketVerdict::Accept { mark: 0x99 }
        ));

        let deny_verdict = timeout_fallback_verdict(11, Some(11), DefaultAction::Deny, 0x99, None);
        assert!(matches!(deny_verdict, PacketVerdict::Drop));

        let reject_verdict =
            timeout_fallback_verdict(11, Some(11), DefaultAction::Reject, 0x99, None);
        assert!(matches!(reject_verdict, PacketVerdict::Drop));
    }

    #[test]
    fn timeout_still_requeues_on_primary_queue() {
        let verdict = timeout_fallback_verdict(10, Some(11), DefaultAction::Deny, 0x44, None);
        assert!(matches!(
            verdict,
            PacketVerdict::Requeue {
                queue_num: 11,
                mark: 0x44
            }
        ));
    }

    #[test]
    fn c_verdict_encoding_matches_expected_values() {
        assert_eq!(
            packet_verdict_to_c(&PacketVerdict::Accept { mark: 7 }),
            (NF_ACCEPT, 7)
        );
        assert_eq!(packet_verdict_to_c(&PacketVerdict::Drop), (NF_DROP, 0));
        assert_eq!(
            packet_verdict_to_c(&PacketVerdict::Requeue {
                queue_num: 6,
                mark: 77,
            }),
            (NF_QUEUE | ((6_u32) << 16), 77)
        );
    }

    #[test]
    fn verdict_with_packet_exposes_payload_for_nfq_set_verdict2() {
        let verdict = PacketVerdict::AcceptWithPacket {
            mark: 7,
            packet: vec![1, 2, 3],
        };

        assert_eq!(packet_verdict_to_c(&verdict), (NF_ACCEPT, 7));
        assert_eq!(packet_verdict_payload(&verdict), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn timeout_flow_requeue_then_allow_on_repeat_queue() {
        let (first, second) = simulate_timeout_flow(20, 21, DefaultAction::Allow, 0x42);

        assert!(matches!(
            first,
            PacketVerdict::Requeue {
                queue_num: 21,
                mark: 0x42
            }
        ));
        assert!(matches!(second, PacketVerdict::Accept { mark: 0x42 }));
    }

    #[test]
    fn timeout_flow_requeue_then_drop_on_repeat_queue() {
        let (first, second) = simulate_timeout_flow(30, 31, DefaultAction::Deny, 0xbeef);

        assert!(matches!(
            first,
            PacketVerdict::Requeue {
                queue_num: 31,
                mark: 0xbeef
            }
        ));
        assert!(matches!(second, PacketVerdict::Drop));
    }

    #[test]
    fn queue_metrics_account_packet_verdicts_and_recv_errors() {
        let _guard = queue_metrics_test_guard();
        reset_queue_metrics_for_test();

        record_packet_verdict(7, &PacketVerdict::Accept { mark: 1 });
        record_packet_verdict(7, &PacketVerdict::Drop);
        record_packet_verdict(
            7,
            &PacketVerdict::Requeue {
                queue_num: 8,
                mark: 2,
            },
        );
        record_recv_error(7);
        record_recv_error(7);

        let metrics = queue_metrics_snapshot_for_test(7);
        assert_eq!(metrics.packets_total, 3);
        assert_eq!(metrics.verdict_accept, 1);
        assert_eq!(metrics.verdict_drop, 1);
        assert_eq!(metrics.verdict_requeue, 1);
        assert_eq!(metrics.recv_errors, 2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_metrics_snapshot_reports_sorted_queues() {
        let _guard = queue_metrics_test_guard();
        reset_queue_metrics_for_test();

        record_packet_verdict(9, &PacketVerdict::Accept { mark: 10 });
        record_packet_verdict(8, &PacketVerdict::Drop);
        record_recv_error(8);

        let snapshot = debug_metrics_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].queue_num, 8);
        assert_eq!(snapshot[1].queue_num, 9);
        assert_eq!(snapshot[0].packets_total, 1);
        assert_eq!(snapshot[0].verdict_drop, 1);
        assert_eq!(snapshot[0].recv_errors, 1);
        assert_eq!(snapshot[1].packets_total, 1);
        assert_eq!(snapshot[1].verdict_accept, 1);
    }
}

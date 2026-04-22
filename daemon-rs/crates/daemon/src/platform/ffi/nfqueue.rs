use std::{
    collections::HashMap,
    ffi::c_void,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::raw::{c_char, c_int},
    ptr,
    sync::{
        Condvar, Mutex, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
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
    bus::Bus,
    config::DefaultAction,
    models::{
        connection_state::{ConnectionAttempt, TransportProtocol},
        dns_payload::DnsPayload,
        kernel_event::KernelEvent,
    },
    platform::adapters::socket_diag::SocketDiagAdapter,
    tunables::NfqueueOverloadPolicy,
};

pub use crate::models::queue_metrics_snapshot::QueueMetricsSnapshot;

pub(crate) const NF_DROP: u32 = 0;
pub(crate) const NF_ACCEPT: u32 = 1;
pub(crate) const NF_QUEUE: u32 = 3;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_CFG_F_UID_GID: u32 = 1 << 3;

const DEFAULT_PACKET_SIZE: u32 = 4096;
const DEFAULT_QUEUE_SIZE: u32 = 4096;
const DEFAULT_SOCKET_RCVBUF_BYTES: i32 = 8 * 1024 * 1024;
const DECISION_SHARD_COUNT: usize = 64;
const PACKET_SIGNATURE_BYTES: usize = 96;
pub(crate) const PRIMARY_DECISION_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const REPEAT_DECISION_TIMEOUT: Duration = Duration::from_secs(120);
const REQUEUE_ALIAS_TTL: Duration = Duration::from_secs(5);

struct DecisionShard {
    decisions: Mutex<HashMap<u64, Option<Decision>>>,
    cv: Condvar,
}

pub(crate) struct RuntimeState {
    bus: Bus,
    repeat_queue_num: u16,
    default_action: AtomicU8,
    overload_policy: AtomicU8,
    uid_support: AtomicU8,
    gid_support: AtomicU8,
    decision_shards: Vec<DecisionShard>,
    requeue_aliases: Mutex<HashMap<u64, RequeueAlias>>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct QueueMetrics {
    packets_total: u64,
    verdict_accept: u64,
    verdict_drop: u64,
    verdict_requeue: u64,
    recv_errors: u64,
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum CapabilitySupport {
    Unknown = 0,
    Supported = 1,
    Unsupported = 2,
}

impl CapabilitySupport {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Supported,
            2 => Self::Unsupported,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Decision {
    pub(crate) allow: bool,
    pub(crate) reject: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct RequeueAlias {
    pub(crate) request_id: u64,
    pub(crate) expires_at: Instant,
}

#[derive(Clone)]
pub(crate) struct RejectSocketSpec {
    family: u8,
    ipproto: u8,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
}

pub(crate) static RUNTIME: OnceLock<RuntimeState> = OnceLock::new();
static QUEUE_METRICS: OnceLock<Mutex<HashMap<u16, QueueMetrics>>> = OnceLock::new();

pub(crate) struct NfqueueRuntimeState;

impl NfqueueRuntimeState {
    fn encode_default_action(action: DefaultAction) -> u8 {
        match action {
            DefaultAction::Allow => 0,
            DefaultAction::Deny => 1,
            DefaultAction::Reject => 2,
        }
    }

    fn decode_default_action(value: u8) -> DefaultAction {
        match value {
            1 => DefaultAction::Deny,
            2 => DefaultAction::Reject,
            _ => DefaultAction::Allow,
        }
    }

    fn current_default_action() -> DefaultAction {
        let Some(runtime) = RUNTIME.get() else {
            return DefaultAction::Allow;
        };

        Self::decode_default_action(runtime.default_action.load(Ordering::Relaxed))
    }

    fn encode_overload_policy(policy: NfqueueOverloadPolicy) -> u8 {
        match policy {
            NfqueueOverloadPolicy::FailOpen => 0,
            NfqueueOverloadPolicy::DropFast => 1,
        }
    }

    fn decode_overload_policy(value: u8) -> NfqueueOverloadPolicy {
        match value {
            1 => NfqueueOverloadPolicy::DropFast,
            _ => NfqueueOverloadPolicy::FailOpen,
        }
    }

    fn current_overload_policy() -> NfqueueOverloadPolicy {
        let Some(runtime) = RUNTIME.get() else {
            return NfqueueOverloadPolicy::FailOpen;
        };

        Self::decode_overload_policy(runtime.overload_policy.load(Ordering::Relaxed))
    }

    pub(crate) fn init(
        bus: Bus,
        primary_queue_num: u16,
        default_action: DefaultAction,
        overload_policy: NfqueueOverloadPolicy,
    ) {
        let _ = RUNTIME.set(RuntimeState {
            bus,
            repeat_queue_num: primary_queue_num.saturating_add(1),
            default_action: AtomicU8::new(Self::encode_default_action(default_action)),
            overload_policy: AtomicU8::new(Self::encode_overload_policy(overload_policy)),
            uid_support: AtomicU8::new(CapabilitySupport::Unknown as u8),
            gid_support: AtomicU8::new(CapabilitySupport::Unknown as u8),
            decision_shards: (0..DECISION_SHARD_COUNT)
                .map(|_| DecisionShard {
                    decisions: Mutex::new(HashMap::new()),
                    cv: Condvar::new(),
                })
                .collect(),
            requeue_aliases: Mutex::new(HashMap::new()),
        });
    }

    pub(crate) fn set_default_action(action: DefaultAction) {
        let Some(runtime) = RUNTIME.get() else {
            return;
        };

        runtime
            .default_action
            .store(Self::encode_default_action(action), Ordering::Relaxed);
    }

    pub(crate) fn submit_verdict(request_id: u64, allow: bool, reject: bool) {
        let Some(runtime) = RUNTIME.get() else {
            return;
        };
        let shard = NfqueueDecisionState::decision_shard(runtime, request_id);

        let mut guard = shard
            .decisions
            .lock()
            .expect("nfqueue decision mutex poisoned");
        if !NfqueueDecisionState::store_decision_if_pending(
            &mut guard,
            request_id,
            Decision { allow, reject },
        ) {
            debug!(
                request_id,
                "ignoring late verdict reply for non-pending request"
            );
            return;
        }
        shard.cv.notify_all();
    }

    pub(crate) fn run(queue_num: u16, shutdown: CancellationToken) -> Result<()> {
        debug!(queue_num, backend = "ffi", "starting nfqueue backend");
        let q = QueueRuntime::open(queue_num)?;
        q.run(shutdown)
    }
}

pub(crate) struct NfqueueMetricsState;
pub(crate) struct NfqueueDecisionState;
pub(crate) struct NfqueuePacketParser;
pub(crate) struct NfqueueVerdictEngine;

impl NfqueueMetricsState {
    pub(crate) fn queue_metrics_map() -> &'static Mutex<HashMap<u16, QueueMetrics>> {
        QUEUE_METRICS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn to_snapshot(queue_num: u16, metrics: QueueMetrics) -> QueueMetricsSnapshot {
        QueueMetricsSnapshot {
            queue_num,
            packets_total: metrics.packets_total,
            verdict_accept: metrics.verdict_accept,
            verdict_drop: metrics.verdict_drop,
            verdict_requeue: metrics.verdict_requeue,
            recv_errors: metrics.recv_errors,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn debug_metrics_snapshot() -> Vec<QueueMetricsSnapshot> {
        let Ok(metrics_map) = Self::queue_metrics_map().lock() else {
            return Vec::new();
        };

        let mut out: Vec<_> = metrics_map
            .iter()
            .map(|(queue_num, metrics)| Self::to_snapshot(*queue_num, *metrics))
            .collect();
        out.sort_by_key(|item| item.queue_num);
        out
    }

    pub(crate) fn record_packet_verdict(queue_num: u16, verdict: &PacketVerdict) {
        let Ok(mut metrics_map) = Self::queue_metrics_map().lock() else {
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

    pub(crate) fn record_recv_error(queue_num: u16) {
        let Ok(mut metrics_map) = Self::queue_metrics_map().lock() else {
            return;
        };
        let entry = metrics_map.entry(queue_num).or_default();
        entry.recv_errors = entry.recv_errors.saturating_add(1);
    }

    fn maybe_log_queue_metrics(queue_num: u16, last_log: &mut Instant) {
        if last_log.elapsed() < Duration::from_secs(60) {
            return;
        }
        *last_log = Instant::now();

        let Ok(metrics_map) = Self::queue_metrics_map().lock() else {
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
}

impl NfqueueDecisionState {
    fn decision_shard(runtime: &RuntimeState, request_id: u64) -> &DecisionShard {
        &runtime.decision_shards[(request_id as usize) & (DECISION_SHARD_COUNT - 1)]
    }

    pub(crate) fn store_decision_if_pending(
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

    pub(crate) fn wait_for_decision(
        request_id: u64,
        timeout: Duration,
        keep_pending_on_timeout: bool,
    ) -> Option<Decision> {
        let runtime = RUNTIME.get()?;
        let shard = Self::decision_shard(runtime, request_id);
        let mut guard = shard.decisions.lock().ok()?;
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
            let (g, _) = shard.cv.wait_timeout(guard, remain).ok()?;
            guard = g;
        }
    }

    pub(crate) fn decision_timeout_for_queue(
        queue_num: u16,
        repeat_queue_num: Option<u16>,
    ) -> Duration {
        if Some(queue_num) == repeat_queue_num {
            REPEAT_DECISION_TIMEOUT
        } else {
            PRIMARY_DECISION_TIMEOUT
        }
    }

    pub(crate) fn should_keep_pending_on_timeout(
        queue_num: u16,
        repeat_queue_num: Option<u16>,
    ) -> bool {
        repeat_queue_num.is_some() && Some(queue_num) != repeat_queue_num
    }

    pub(crate) fn packet_signature(payload: &[u8], uid: u32, mark: u32) -> u64 {
        let mut hash = 0xcbf29ce484222325_u64;
        for b in uid.to_le_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in mark.to_le_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in (payload.len() as u64).to_le_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in payload.iter().take(PACKET_SIGNATURE_BYTES) {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    pub(crate) fn prune_requeue_aliases(aliases: &mut HashMap<u64, RequeueAlias>) {
        let now = Instant::now();
        aliases.retain(|_, alias| alias.expires_at > now);
    }

    fn resolve_request_id(
        queue_num: u16,
        packet_id: u32,
        payload_signature: u64,
        repeat_queue_num: Option<u16>,
    ) -> u64 {
        if Some(queue_num) == repeat_queue_num
            && let Some(request_id) = Self::claim_requeue_alias(payload_signature)
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

        Self::prune_requeue_aliases(&mut aliases);
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
        Self::prune_requeue_aliases(&mut aliases);
        aliases
            .remove(&payload_signature)
            .map(|alias| alias.request_id)
    }
}

impl NfqueuePacketParser {
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

        let uid_state = CapabilitySupport::from_u8(runtime.uid_support.load(Ordering::Relaxed));
        if !matches!(uid_state, CapabilitySupport::Unsupported) {
            let rc = unsafe { nfq_get_uid(nfa, &mut uid as *mut u32) };
            if rc >= 0 {
                if matches!(uid_state, CapabilitySupport::Unknown) {
                    let _ = runtime.uid_support.compare_exchange(
                        CapabilitySupport::Unknown as u8,
                        CapabilitySupport::Supported as u8,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
            } else if matches!(uid_state, CapabilitySupport::Unknown)
                && runtime
                    .uid_support
                    .compare_exchange(
                        CapabilitySupport::Unknown as u8,
                        CapabilitySupport::Unsupported as u8,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                warn!("nfqueue uid metadata unavailable; continuing without uid extraction");
            }
        }

        let gid_state = CapabilitySupport::from_u8(runtime.gid_support.load(Ordering::Relaxed));
        if !matches!(gid_state, CapabilitySupport::Unsupported) {
            let rc = unsafe { nfq_get_gid(nfa, &mut gid as *mut u32) };
            if rc >= 0 {
                if matches!(gid_state, CapabilitySupport::Unknown) {
                    let _ = runtime.gid_support.compare_exchange(
                        CapabilitySupport::Unknown as u8,
                        CapabilitySupport::Supported as u8,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
            } else if matches!(gid_state, CapabilitySupport::Unknown)
                && runtime
                    .gid_support
                    .compare_exchange(
                        CapabilitySupport::Unknown as u8,
                        CapabilitySupport::Unsupported as u8,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                warn!("nfqueue gid metadata unavailable; continuing without gid extraction");
            }
        }

        (uid, gid)
    }

    pub(crate) fn parse_dns_answer_mappings(payload: &[u8]) -> Vec<(IpAddr, String)> {
        let Some((udp_offset, src_port, _dst_port)) = Self::udp_offsets(payload) else {
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
            let Some((name, next)) = Self::parse_dns_name(dns, pos) else {
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
            let Some((_answer_name, next)) = Self::parse_dns_name(dns, pos) else {
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
                        out.push((IpAddr::V4(ip), question_name.clone()));
                    }
                }
                28 if rdlen == 16 => {
                    if let Ok(octets) = <[u8; 16]>::try_from(&dns[rdata_off..rdata_off + 16]) {
                        if !question_name.is_empty() {
                            out.push((IpAddr::V6(Ipv6Addr::from(octets)), question_name.clone()));
                        }
                    }
                }
                5 => {
                    // CNAME aliases are handled by the DNS worker, not nfqueue
                }
                _ => {}
            }

            pos = rdata_off + rdlen;
        }

        out
    }

    pub(crate) fn parse_dns_last_question(payload: &[u8]) -> Option<String> {
        if let Some((udp_offset, _src_port, dst_port)) = Self::udp_offsets(payload)
            && dst_port == 53
            && payload.len() >= udp_offset + 8
        {
            return Self::parse_dns_last_question_name(&payload[udp_offset + 8..]);
        }

        if let Some((tcp_offset, _src_port, dst_port, tcp_header_len)) = Self::tcp_offsets(payload)
            && dst_port == 53
        {
            let dns_off = tcp_offset + tcp_header_len;
            if payload.len() >= dns_off + 2 {
                let declared_len =
                    u16::from_be_bytes([payload[dns_off], payload[dns_off + 1]]) as usize;
                let dns_start = dns_off + 2;
                let dns_end = dns_start.saturating_add(declared_len).min(payload.len());
                if dns_end > dns_start {
                    return Self::parse_dns_last_question_name(&payload[dns_start..dns_end]);
                }
            }
        }

        None
    }

    pub(crate) fn parse_connection_attempt(
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
            4 => Self::parse_ipv4_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx),
            6 => Self::parse_ipv6_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx),
            _ => None,
        }
    }

    fn build_reject_socket_spec(attempt: &ConnectionAttempt) -> Option<RejectSocketSpec> {
        let family = Self::infer_family(attempt);
        let ipproto = Self::protocol_to_ipproto(attempt.protocol)?;
        Some(RejectSocketSpec {
            family,
            ipproto,
            src: attempt.src_addr,
            src_port: attempt.src_port,
            dst: attempt.dst_addr,
            dst_port: attempt.dst_port,
        })
    }

    fn infer_family(attempt: &ConnectionAttempt) -> u8 {
        match attempt.src_addr {
            IpAddr::V6(_) => libc::AF_INET6 as u8,
            IpAddr::V4(_) => libc::AF_INET as u8,
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

    fn parse_dns_last_question_name(dns: &[u8]) -> Option<String> {
        if dns.len() < 12 {
            return None;
        }

        let qdcount = u16::from_be_bytes([dns[4], dns[5]]) as usize;
        let mut pos = 12_usize;
        let mut last = None;

        for _ in 0..qdcount {
            let Some((name, next)) = Self::parse_dns_name(dns, pos) else {
                break;
            };
            if dns.len() < next + 4 {
                break;
            }
            if !name.is_empty() {
                // Normalise to lower-case: DNS names are case-insensitive
                // (RFC 4343) and all downstream comparisons expect lower-case.
                last = Some(name.to_lowercase());
            }
            pos = next + 4;
        }

        last
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

        let src_addr = IpAddr::V4(Ipv4Addr::new(
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ));

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
            src_addr,
            src_port,
            dst_addr,
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

        let src_addr = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[8..24]).ok()?));
        let dst_addr = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[24..40]).ok()?));

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
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            iface_in_idx,
            iface_out_idx,
            dns_query: None,
            pid: 0,
            uid,
        })
    }
}

#[derive(Clone)]
pub(crate) enum PacketVerdict {
    Accept {
        mark: u32,
    },
    #[cfg_attr(not(test), allow(dead_code))]
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

impl NfqueueVerdictEngine {
    pub(crate) fn timeout_fallback_verdict(
        queue_num: u16,
        repeat_queue_num: Option<u16>,
        overload_policy: NfqueueOverloadPolicy,
        default_action: DefaultAction,
        mark: u32,
        reject_spec: Option<&RejectSocketSpec>,
    ) -> PacketVerdict {
        if matches!(overload_policy, NfqueueOverloadPolicy::DropFast) {
            warn!(
                queue_num,
                fallback_reason = "timeout",
                fallback_mode = "drop-fast",
                "nfqueue overload fallback final verdict"
            );
            return PacketVerdict::Drop;
        }

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

        let verdict =
            Self::default_action_verdict_for_reject_spec(default_action, mark, reject_spec);

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

    pub(crate) fn packet_verdict_to_c(verdict: &PacketVerdict) -> (u32, u32) {
        match verdict {
            PacketVerdict::Accept { mark } => (NF_ACCEPT, *mark),
            PacketVerdict::AcceptWithPacket { mark, .. } => (NF_ACCEPT, *mark),
            PacketVerdict::Drop => (NF_DROP, 0),
            PacketVerdict::Requeue { queue_num, mark } => {
                (NF_QUEUE | ((*queue_num as u32) << 16), *mark)
            }
        }
    }

    pub(crate) fn packet_verdict_payload(verdict: &PacketVerdict) -> Option<&[u8]> {
        match verdict {
            PacketVerdict::AcceptWithPacket { packet, .. } if !packet.is_empty() => Some(packet),
            _ => None,
        }
    }

    pub(crate) fn compute_packet_verdict(
        queue_num: u16,
        packet_id: u32,
        payload: &[u8],
        uid: u32,
        mark: u32,
        iface_in_idx: u32,
        iface_out_idx: u32,
    ) -> PacketVerdict {
        let runtime = RUNTIME.get();
        let default_action = NfqueueRuntimeState::current_default_action();
        let overload_policy = NfqueueRuntimeState::current_overload_policy();
        let dns_answers = NfqueuePacketParser::parse_dns_answer_mappings(payload);
        let is_dns_response = !dns_answers.is_empty();

        if let Some(runtime) = runtime {
            for (addr, host) in dns_answers {
                let _ = runtime
                    .bus
                    .kernel_tx
                    .try_send(KernelEvent::DnsUpdate(DnsPayload::answer(host, addr)));
            }
        }

        if is_dns_response {
            return PacketVerdict::Accept { mark };
        }

        let repeat_queue_num = runtime.map(|state| state.repeat_queue_num);
        let mut payload_signature = None;
        let signature_for_request = if Some(queue_num) == repeat_queue_num {
            let signature = NfqueueDecisionState::packet_signature(payload, uid, mark);
            payload_signature = Some(signature);
            signature
        } else {
            0
        };
        let request_id = NfqueueDecisionState::resolve_request_id(
            queue_num,
            packet_id,
            signature_for_request,
            repeat_queue_num,
        );

        if let Some(mut attempt) = NfqueuePacketParser::parse_connection_attempt(
            request_id,
            payload,
            uid,
            iface_in_idx,
            iface_out_idx,
        ) {
            if attempt.dst_port == 53 {
                attempt.dns_query = NfqueuePacketParser::parse_dns_last_question(payload);
            }
            let reject_spec = NfqueuePacketParser::build_reject_socket_spec(&attempt);

            if let Some(runtime) = runtime
                && let Err(_attempt) =
                    Self::enqueue_connect_attempt_non_blocking(&runtime.bus, attempt)
            {
                debug!(
                    request_id,
                    queue_num, "kernel event queue saturated, applying timeout fallback verdict"
                );
                return Self::timeout_fallback_verdict(
                    queue_num,
                    repeat_queue_num,
                    overload_policy,
                    default_action,
                    mark,
                    reject_spec.as_ref(),
                );
            }

            let decision_timeout =
                NfqueueDecisionState::decision_timeout_for_queue(queue_num, repeat_queue_num);
            let keep_pending_on_timeout =
                NfqueueDecisionState::should_keep_pending_on_timeout(queue_num, repeat_queue_num);

            let decision = match NfqueueDecisionState::wait_for_decision(
                request_id,
                decision_timeout,
                keep_pending_on_timeout,
            ) {
                Some(decision) => decision,
                None => {
                    if keep_pending_on_timeout {
                        let signature = payload_signature.get_or_insert_with(|| {
                            NfqueueDecisionState::packet_signature(payload, uid, mark)
                        });
                        NfqueueDecisionState::remember_requeue_alias(*signature, request_id);
                    }

                    return Self::timeout_fallback_verdict(
                        queue_num,
                        repeat_queue_num,
                        overload_policy,
                        default_action,
                        mark,
                        reject_spec.as_ref(),
                    );
                }
            };

            if !decision.allow
                && decision.reject
                && let Some(spec) = reject_spec.as_ref()
            {
                Self::reject_socket_for_spec(spec);
            }

            return if decision.allow {
                PacketVerdict::Accept { mark }
            } else {
                PacketVerdict::Drop
            };
        }

        Self::default_action_verdict(default_action, mark)
    }

    pub(crate) fn enqueue_connect_attempt_non_blocking(
        bus: &Bus,
        attempt: ConnectionAttempt,
    ) -> std::result::Result<(), ConnectionAttempt> {
        match bus.connect_tx.try_send(attempt) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => Err(attempt),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(attempt)) => Err(attempt),
        }
    }

    fn default_action_verdict(action: DefaultAction, mark: u32) -> PacketVerdict {
        Self::default_action_verdict_for_reject_spec(action, mark, None)
    }

    fn default_action_verdict_for_reject_spec(
        action: DefaultAction,
        mark: u32,
        reject_spec: Option<&RejectSocketSpec>,
    ) -> PacketVerdict {
        if action.allows() {
            PacketVerdict::Accept { mark }
        } else {
            if action.rejects()
                && let Some(spec) = reject_spec
            {
                Self::reject_socket_for_spec(spec);
            }
            PacketVerdict::Drop
        }
    }

    fn reject_socket_for_spec(spec: &RejectSocketSpec) {
        if let Ok(Some(sock)) = SocketDiagAdapter::find_socket(
            spec.family,
            spec.ipproto,
            spec.src,
            spec.src_port,
            spec.dst,
            spec.dst_port,
        ) {
            let _ = SocketDiagAdapter::kill_socket(spec.family, spec.ipproto, &sock);
        }
    }
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

            let qh = nfq_create_queue(
                h,
                queue_num,
                Some(nfqueue_callback),
                queue_num as usize as *mut c_void,
            );
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

            Self::tune_netlink_no_enobufs(fd);
            Self::tune_socket_recv_buffer(fd, DEFAULT_SOCKET_RCVBUF_BYTES);

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
            NfqueueMetricsState::maybe_log_queue_metrics(self.queue_num, &mut last_metrics_log);

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
                        NfqueueMetricsState::record_recv_error(self.queue_num);
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
                NfqueueMetricsState::record_recv_error(self.queue_num);
                warn!("nfqueue recv returned EOF");
                continue;
            }

            if recv_rc > c_int::MAX as usize {
                NfqueueMetricsState::record_recv_error(self.queue_num);
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
}

impl Drop for QueueRuntime {
    fn drop(&mut self) {
        // SAFETY: pointers are created by libnetfilter_queue and may be null.
        unsafe {
            if !self.qh.is_null() {
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

unsafe extern "C" fn nfqueue_callback(
    qh: *mut nfq_q_handle,
    _nfmsg: *mut nfgenmsg,
    nfa: *mut nfq_data,
    data: *mut c_void,
) -> c_int {
    let queue_num = data as usize as u16;

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

    let (uid, _) = NfqueuePacketParser::read_uid_gid(nfa);
    let mark = unsafe { nfq_get_nfmark(nfa) };

    let iface_in_idx = unsafe { nfq_get_indev(nfa) };
    let iface_out_idx = unsafe { nfq_get_outdev(nfa) };

    let packet_verdict = NfqueueVerdictEngine::compute_packet_verdict(
        queue_num,
        packet_id,
        payload,
        uid,
        mark,
        iface_in_idx,
        iface_out_idx,
    );
    NfqueueMetricsState::record_packet_verdict(queue_num, &packet_verdict);

    let (verdict, verdict_mark) = NfqueueVerdictEngine::packet_verdict_to_c(&packet_verdict);
    let (data_len, data_ptr) =
        if let Some(packet) = NfqueueVerdictEngine::packet_verdict_payload(&packet_verdict) {
            (packet.len() as u32, packet.as_ptr())
        } else {
            (0_u32, ptr::null())
        };

    unsafe { nfq_set_verdict2(qh, packet_id, verdict, verdict_mark, data_len, data_ptr) }
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

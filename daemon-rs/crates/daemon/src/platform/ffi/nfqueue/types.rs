use std::{
    collections::HashMap,
    ffi::c_void,
    net::IpAddr,
    os::raw::{c_char, c_int},
    sync::{Condvar, Mutex, OnceLock, atomic::AtomicU8},
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::bus::Bus;

pub(crate) const NF_DROP: u32 = 0;
pub(crate) const NF_ACCEPT: u32 = 1;
pub(crate) const NF_QUEUE: u32 = 3;
pub(super) const NFQNL_COPY_PACKET: u8 = 2;
pub(super) const NFQA_CFG_F_UID_GID: u32 = 1 << 3;

pub(super) const DEFAULT_PACKET_SIZE: u32 = 4096;
pub(super) const DEFAULT_QUEUE_SIZE: u32 = 4096;
pub(super) const DEFAULT_SOCKET_RCVBUF_BYTES: i32 = 8 * 1024 * 1024;
pub(super) const DECISION_SHARD_COUNT: usize = 64;
pub(super) const PACKET_SIGNATURE_BYTES: usize = 96;
pub(crate) const PRIMARY_DECISION_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const REPEAT_DECISION_TIMEOUT: Duration = Duration::from_secs(120);
pub(super) const REQUEUE_ALIAS_TTL: Duration = Duration::from_secs(5);

pub(super) struct DecisionShard {
    pub(super) decisions: Mutex<HashMap<u64, Option<Decision>>>,
    pub(super) cv: Condvar,
}

pub(crate) struct RuntimeState {
    pub(super) bus: Bus,
    pub(super) repeat_queue_num: u16,
    pub(super) default_action: AtomicU8,
    pub(super) overload_policy: AtomicU8,
    pub(super) uid_support: AtomicU8,
    pub(super) gid_support: AtomicU8,
    pub(super) decision_shards: Vec<DecisionShard>,
    pub(super) requeue_aliases: DashMap<u64, RequeueAlias>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct QueueMetrics {
    pub(super) packets_total: u64,
    pub(super) verdict_accept: u64,
    pub(super) verdict_drop: u64,
    pub(super) verdict_requeue: u64,
    pub(super) recv_errors: u64,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub(super) enum CapabilitySupport {
    Unknown = 0,
    Supported = 1,
    Unsupported = 2,
}

impl CapabilitySupport {
    pub(super) fn from_u8(value: u8) -> Self {
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
    pub(super) family: u8,
    pub(super) ipproto: u8,
    pub(super) src: IpAddr,
    pub(super) src_port: u16,
    pub(super) dst: IpAddr,
    pub(super) dst_port: u16,
}

pub(crate) static RUNTIME: OnceLock<RuntimeState> = OnceLock::new();
pub(super) static QUEUE_METRICS: OnceLock<Mutex<HashMap<u16, QueueMetrics>>> = OnceLock::new();

pub(crate) struct NfqueueRuntimeState;
pub(crate) struct NfqueueMetricsState;
pub(crate) struct NfqueueDecisionState;
pub(crate) struct NfqueuePacketParser;
pub(crate) struct NfqueueVerdictEngine;

#[derive(Clone)]
pub(crate) enum PacketVerdict {
    Accept {
        mark: u32,
    },
    // Optional verdict variant retained for packet-rewrite paths not active in baseline profiles.
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

pub(super) struct QueueRuntime {
    pub(super) h: *mut nfq_handle,
    pub(super) qh: *mut nfq_q_handle,
    pub(super) fd: c_int,
    pub(super) queue_num: u16,
}

// SAFETY: QueueRuntime wraps C pointers that are only accessed on the single queue
// thread and cleaned up in Drop. Covenanting to not share raw pointers across threads.
unsafe impl Send for QueueRuntime {}

#[repr(C)]
pub(super) struct nfq_handle {
    pub(super) _private: [u8; 0],
}

#[repr(C)]
pub(super) struct nfq_q_handle {
    pub(super) _private: [u8; 0],
}

#[repr(C)]
pub(super) struct nfgenmsg {
    pub(super) _private: [u8; 0],
}

#[repr(C)]
pub(super) struct nfq_data {
    pub(super) _private: [u8; 0],
}

#[repr(C)]
pub(super) struct nfqnl_msg_packet_hdr {
    pub(super) packet_id: u32,
    pub(super) hw_protocol: u16,
    pub(super) hook: u8,
}

pub(super) type NfqCallback =
    unsafe extern "C" fn(*mut nfq_q_handle, *mut nfgenmsg, *mut nfq_data, *mut c_void) -> c_int;

#[link(name = "netfilter_queue")]
unsafe extern "C" {
    pub(super) fn nfq_open() -> *mut nfq_handle;
    pub(super) fn nfq_close(h: *mut nfq_handle) -> c_int;
    pub(super) fn nfq_unbind_pf(h: *mut nfq_handle, pf: u16) -> c_int;
    pub(super) fn nfq_bind_pf(h: *mut nfq_handle, pf: u16) -> c_int;

    pub(super) fn nfq_create_queue(
        h: *mut nfq_handle,
        num: u16,
        cb: Option<NfqCallback>,
        data: *mut c_void,
    ) -> *mut nfq_q_handle;
    pub(super) fn nfq_destroy_queue(qh: *mut nfq_q_handle) -> c_int;

    pub(super) fn nfq_set_mode(qh: *mut nfq_q_handle, mode: u8, range: u32) -> c_int;
    pub(super) fn nfq_set_queue_maxlen(qh: *mut nfq_q_handle, queuelen: u32) -> c_int;
    pub(super) fn nfq_set_queue_flags(qh: *mut nfq_q_handle, mask: u32, flags: u32) -> c_int;
    pub(super) fn nfq_fd(h: *mut nfq_handle) -> c_int;

    pub(super) fn nfq_handle_packet(h: *mut nfq_handle, buf: *mut c_char, len: c_int) -> c_int;
    pub(super) fn nfq_get_msg_packet_hdr(tb: *mut nfq_data) -> *mut nfqnl_msg_packet_hdr;
    pub(super) fn nfq_get_payload(tb: *mut nfq_data, data: *mut *mut u8) -> c_int;
    pub(super) fn nfq_get_uid(tb: *mut nfq_data, uid: *mut u32) -> c_int;
    pub(super) fn nfq_get_gid(tb: *mut nfq_data, gid: *mut u32) -> c_int;
    pub(super) fn nfq_get_indev(tb: *mut nfq_data) -> u32;
    pub(super) fn nfq_get_outdev(tb: *mut nfq_data) -> u32;
    pub(super) fn nfq_get_nfmark(tb: *mut nfq_data) -> u32;

    pub(super) fn nfq_set_verdict2(
        qh: *mut nfq_q_handle,
        id: u32,
        verdict: u32,
        mark: u32,
        datalen: u32,
        buf: *const u8,
    ) -> c_int;
}

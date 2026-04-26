use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Condvar, Mutex, OnceLock, atomic::AtomicU8},
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::bus::Bus;

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

pub(crate) struct NfqueueRuntimeState {
    pub(super) bus: Bus,
    pub(super) repeat_queue_num: u16,
    pub(super) default_action: AtomicU8,
    pub(super) overload_policy: AtomicU8,
    pub(super) uid_support: AtomicU8,
    pub(super) gid_support: AtomicU8,
    pub(super) decision_shards: Vec<DecisionShard>,
    pub(super) requeue_aliases: DashMap<u64, RequeueAlias>,
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

pub(crate) static RUNTIME: OnceLock<NfqueueRuntimeState> = OnceLock::new();

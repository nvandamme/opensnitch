pub(super) use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[cfg(any(feature = "aya-ebpf", feature = "libbpf-ebpf"))]
pub(super) use ebpf_common::maps::EVENTS_MAP_NAME;
pub(super) use tokio_util::sync::CancellationToken;
pub(super) use tracing::{debug, info, trace, warn};

pub(super) use crate::bus::Bus;
#[cfg(feature = "native-ebpf-ringbuf")]
pub(super) use crate::models::dns::payload::DnsPayload;
pub(super) use crate::models::kernel::event::KernelEvent;
#[cfg(feature = "native-ebpf-ringbuf")]
pub(super) use crate::platform::procmon::ebpf_payload::EbpfProcStatePayload;
#[cfg(feature = "native-ebpf-ringbuf")]
pub(super) use crate::services::dns::{DnsDedupKey, DnsEbpfEventDeduper, DnsService};
#[cfg(feature = "native-ebpf-ringbuf")]
pub(super) use crate::services::ebpf::EbpfRingbufConsumer;
pub(super) use crate::services::ebpf::{EbpfPinDomain, EbpfService};
#[cfg(feature = "native-ebpf-ringbuf")]
pub(super) use crate::services::process::ProcessService;
pub(super) use crate::tunables::RuntimeTunables;
#[cfg(feature = "native-ebpf-ringbuf")]
pub(super) use crate::utils::byte_read::read_ne_value_at;
pub(super) use crate::workers::runtime::control::{
    WorkerCommandResult, impl_restartable_thread_worker_control,
};
pub(super) use crate::workers::runtime::ebpf::types::RawBpfMap;

mod aya_runtime;
mod bpftool;
mod lifecycle;
mod newtype;
mod supervise;
mod types;

pub(crate) use lifecycle::EbpfWorkerControl;
#[cfg(all(feature = "native-ebpf-ringbuf", test))]
pub(super) use supervise::NativeQueuedEvent;
pub(super) use supervise::{EbpfMapPrunePolicy, NativeRingbuf, SupervisorState};
pub(crate) use types::EbpfWorkerMode;
pub(super) use types::*;

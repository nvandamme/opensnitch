// Ringbuf backend plumbing is retained in no-backend packaging profiles so the
// public service surface stays stable; it becomes active when ebpf features are on.
#![cfg(any(feature = "aya-ebpf", feature = "libbpf-ebpf"))]

use std::time::Duration;

#[cfg(feature = "libbpf-ebpf")]
use std::path::Path;

use anyhow::Result;
use ebpf_common::maps::EVENTS_MAP_MAX_ENTRIES;
#[cfg(any(feature = "libbpf-ebpf", feature = "aya-ebpf"))]
use ebpf_common::maps::EVENTS_MAP_NAME;

#[cfg(feature = "aya-ebpf")]
use std::os::fd::{AsRawFd, BorrowedFd};

#[cfg(feature = "libbpf-ebpf")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "libbpf-ebpf")]
use libbpf_rs::{MapType, query::MapInfoIter};

#[cfg(feature = "aya-ebpf")]
use rustix::event::{PollFd, PollFlags, Timespec, poll};

#[cfg(feature = "aya-ebpf")]
use super::AyaManagedRingbufAsset;
use super::EbpfPinDomain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EbpfRuntimeMode {
    AyaManagedRs,
    AyaLegacyCompat,
    LibbpfLegacyCompat,
    UserspaceFallback,
}

#[derive(Debug)]
pub(crate) enum EbpfRingbufBackendKind {
    #[cfg(feature = "libbpf-ebpf")]
    Libbpf,
    #[cfg(feature = "aya-ebpf")]
    Aya,
}

pub(crate) struct EbpfRingbufConsumer {
    runtime_mode: EbpfRuntimeMode,
    backend_kind: EbpfRingbufBackendKind,
    inner: BackendInner,
}

#[derive(Clone, Copy)]
struct RingbufMapCandidate {
    id: u32,
    is_ringbuf: bool,
    name_matches: bool,
    max_entries: u32,
}

fn select_opensnitch_ringbuf_map_id(
    candidates: impl IntoIterator<Item = RingbufMapCandidate>,
) -> Option<u32> {
    candidates
        .into_iter()
        .filter(|candidate| {
            candidate.is_ringbuf
                && candidate.name_matches
                && candidate.max_entries == EVENTS_MAP_MAX_ENTRIES
        })
        .map(|candidate| candidate.id)
        .max()
}

#[cfg(feature = "aya-ebpf")]
fn aya_poll_has_readable_samples(poll_rc: usize, revents: PollFlags) -> bool {
    poll_rc > 0 && revents.contains(PollFlags::IN)
}

fn runtime_fallback_chain(pin_domain: EbpfPinDomain) -> &'static [EbpfRuntimeMode] {
    match pin_domain {
        EbpfPinDomain::Aya => &[
            EbpfRuntimeMode::AyaManagedRs,
            EbpfRuntimeMode::AyaLegacyCompat,
            EbpfRuntimeMode::LibbpfLegacyCompat,
            EbpfRuntimeMode::UserspaceFallback,
        ],
        EbpfPinDomain::Legacy => &[
            EbpfRuntimeMode::AyaLegacyCompat,
            EbpfRuntimeMode::LibbpfLegacyCompat,
            EbpfRuntimeMode::UserspaceFallback,
        ],
    }
}

fn describe_map_candidates(map_paths: &[&str]) -> String {
    if map_paths.is_empty() {
        return "<none>".to_string();
    }

    map_paths.join(", ")
}

#[cfg(test)]
pub(crate) fn probe_select_opensnitch_ringbuf_map_id(
    candidates: &[(u32, bool, bool, u32)],
) -> Option<u32> {
    select_opensnitch_ringbuf_map_id(candidates.iter().copied().map(
        |(id, is_ringbuf, name_matches, max_entries)| RingbufMapCandidate {
            id,
            is_ringbuf,
            name_matches,
            max_entries,
        },
    ))
}

#[cfg(all(test, feature = "aya-ebpf"))]
pub(crate) fn probe_aya_poll_has_readable_samples(poll_rc: usize, revents: PollFlags) -> bool {
    aya_poll_has_readable_samples(poll_rc, revents)
}

#[cfg(test)]
pub(crate) fn probe_runtime_fallback_chain(pin_domain: EbpfPinDomain) -> Vec<EbpfRuntimeMode> {
    runtime_fallback_chain(pin_domain).to_vec()
}

impl EbpfRingbufConsumer {
    pub(crate) fn try_open_with_diagnostics(
        pin_domain: EbpfPinDomain,
        #[cfg(feature = "aya-ebpf")] managed_aya_ringbuf: Option<AyaManagedRingbufAsset>,
        managed_map_paths: &[&str],
        legacy_map_paths: &[&str],
    ) -> Result<(Self, Vec<String>), String> {
        let mut errors: Vec<String> = Vec::new();
        let managed_paths_present = managed_map_paths
            .iter()
            .any(|path| std::path::Path::new(path).exists());
        #[cfg(not(any(feature = "aya-ebpf", feature = "libbpf-ebpf")))]
        let _ = (legacy_map_paths, managed_paths_present);
        #[cfg(feature = "aya-ebpf")]
        let mut managed_aya_ringbuf = managed_aya_ringbuf;

        for runtime_mode in runtime_fallback_chain(pin_domain) {
            match runtime_mode {
                #[cfg(feature = "aya-ebpf")]
                EbpfRuntimeMode::AyaManagedRs => match AyaRingbuf::try_open_managed(
                    managed_aya_ringbuf.take(),
                    managed_map_paths,
                ) {
                    Ok(inner) => {
                        return Ok((
                            Self {
                                runtime_mode: *runtime_mode,
                                backend_kind: EbpfRingbufBackendKind::Aya,
                                inner: BackendInner::Aya(inner),
                            },
                            errors,
                        ));
                    }
                    Err(err) => errors.push(format!("aya managed-rs: {err}")),
                },

                #[cfg(feature = "aya-ebpf")]
                EbpfRuntimeMode::AyaLegacyCompat => match AyaRingbuf::try_open_legacy_compat(
                    legacy_map_paths,
                    managed_paths_present,
                ) {
                    Ok(inner) => {
                        return Ok((
                            Self {
                                runtime_mode: *runtime_mode,
                                backend_kind: EbpfRingbufBackendKind::Aya,
                                inner: BackendInner::Aya(inner),
                            },
                            errors,
                        ));
                    }
                    Err(err) => errors.push(format!("aya legacy-compat: {err}")),
                },

                #[cfg(feature = "libbpf-ebpf")]
                EbpfRuntimeMode::LibbpfLegacyCompat => match LibbpfRingbuf::try_open_legacy_compat(
                    legacy_map_paths,
                    managed_paths_present,
                ) {
                    Ok(inner) => {
                        return Ok((
                            Self {
                                runtime_mode: *runtime_mode,
                                backend_kind: EbpfRingbufBackendKind::Libbpf,
                                inner: BackendInner::Libbpf(inner),
                            },
                            errors,
                        ));
                    }
                    Err(err) => errors.push(format!("libbpf legacy-compat: {err}")),
                },

                EbpfRuntimeMode::UserspaceFallback => {
                    errors.push("userspace fallback: native ringbuf unavailable".to_string());
                }

                #[cfg(not(feature = "aya-ebpf"))]
                EbpfRuntimeMode::AyaManagedRs | EbpfRuntimeMode::AyaLegacyCompat => {}

                #[cfg(not(feature = "libbpf-ebpf"))]
                EbpfRuntimeMode::LibbpfLegacyCompat => {}
            }
        }

        if errors.is_empty() {
            Err("no eBPF ringbuf backend enabled; enable libbpf-ebpf or aya-ebpf".to_string())
        } else {
            Err(errors.join("; "))
        }
    }

    #[cfg(any(feature = "libbpf-ebpf", feature = "aya-ebpf"))]
    pub(crate) fn poll_samples(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        match &mut self.inner {
            #[cfg(feature = "libbpf-ebpf")]
            BackendInner::Libbpf(inner) => inner.poll_samples(timeout),
            #[cfg(feature = "aya-ebpf")]
            BackendInner::Aya(inner) => inner.poll_samples(timeout),
        }
    }

    #[cfg(not(any(feature = "libbpf-ebpf", feature = "aya-ebpf")))]
    pub(crate) fn poll_samples(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        let _ = timeout;
        Err("no eBPF ringbuf backend enabled".to_string())
    }

    pub(crate) fn backend_kind(&self) -> &EbpfRingbufBackendKind {
        &self.backend_kind
    }

    pub(crate) fn runtime_mode(&self) -> EbpfRuntimeMode {
        self.runtime_mode
    }
}

enum BackendInner {
    #[cfg(feature = "libbpf-ebpf")]
    Libbpf(LibbpfRingbuf),
    #[cfg(feature = "aya-ebpf")]
    Aya(AyaRingbuf),
}

#[cfg(feature = "libbpf-ebpf")]
struct LibbpfRingbuf {
    _map: &'static mut libbpf_rs::MapHandle,
    ringbuf: libbpf_rs::RingBuffer<'static>,
    queue: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[cfg(feature = "libbpf-ebpf")]
impl LibbpfRingbuf {
    fn try_open_legacy_compat(
        map_paths: &[&str],
        managed_paths_present: bool,
    ) -> Result<Self, String> {
        let map = if let Some(map_path) = map_paths.iter().find(|path| Path::new(path).exists()) {
            libbpf_rs::MapHandle::from_pinned_path(map_path)
                .map_err(|err| format!("open pinned ringbuf map failed ({map_path}): {err}"))?
        } else if managed_paths_present {
            return Err(
                "opensnitch-rs managed pin paths are present; refusing legacy direct ringbuf autodiscovery"
                    .to_string(),
            );
        } else if let Some(map_id) = Self::discover_loaded_ringbuf_map_id() {
            libbpf_rs::MapHandle::from_map_id(map_id).map_err(|err| {
                format!("open loaded ringbuf map by id failed (id={map_id}): {err}")
            })?
        } else {
            return Err(format!(
                "no opensnitch ringbuf map found (checked pinned: {}; loaded map scan: none)",
                describe_map_candidates(map_paths)
            ));
        };
        let map = Box::leak(Box::new(map));

        let queue = Arc::new(Mutex::new(Vec::with_capacity(64)));
        let queue_closure = Arc::clone(&queue);

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(map, move |sample: &[u8]| -> i32 {
                if let Ok(mut q) = queue_closure.lock() {
                    q.push(sample.to_vec());
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

    fn discover_loaded_ringbuf_map_id() -> Option<u32> {
        select_opensnitch_ringbuf_map_id(MapInfoIter::default().map(|info| RingbufMapCandidate {
            id: info.id,
            is_ringbuf: info.ty == MapType::RingBuf,
            name_matches: info.name.to_string_lossy() == EVENTS_MAP_NAME,
            max_entries: info.max_entries,
        }))
    }

    fn poll_samples(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.ringbuf
            .poll(timeout)
            .map_err(|err| format!("ringbuf poll failed: {err}"))?;

        let mut queue = self
            .queue
            .lock()
            .map_err(|_| "ringbuf queue lock poisoned".to_string())?;

        Ok(queue.drain(..).collect())
    }
}

#[cfg(feature = "aya-ebpf")]
struct AyaRingbuf {
    source: String,
    ringbuf: aya::maps::RingBuf<aya::maps::MapData>,
}

#[cfg(feature = "aya-ebpf")]
impl AyaRingbuf {
    fn try_open_managed(
        managed_ringbuf: Option<AyaManagedRingbufAsset>,
        map_paths: &[&str],
    ) -> Result<Self, String> {
        let Some(AyaManagedRingbufAsset { source, map_data }) = managed_ringbuf else {
            return Err(format!(
                "no managed opensnitch-rs ringbuf handle available (expected one of: {})",
                describe_map_candidates(map_paths)
            ));
        };

        let map = aya::maps::Map::RingBuf(map_data);
        let ringbuf = aya::maps::RingBuf::try_from(map)
            .map_err(|err| format!("attach aya ringbuf reader failed ({source}): {err}"))?;

        Ok(Self { source, ringbuf })
    }

    fn try_open_legacy_compat(
        map_paths: &[&str],
        managed_paths_present: bool,
    ) -> Result<Self, String> {
        if let Some(map_path) = map_paths
            .iter()
            .find(|path| std::path::Path::new(path).exists())
        {
            let map_data = aya::maps::MapData::from_pin(map_path)
                .map_err(|err| format!("open pinned ringbuf map failed ({map_path}): {err}"))?;

            let map = aya::maps::Map::RingBuf(map_data);
            let ringbuf = aya::maps::RingBuf::try_from(map)
                .map_err(|err| format!("attach aya ringbuf reader failed ({map_path}): {err}"))?;

            return Ok(Self {
                source: (*map_path).to_string(),
                ringbuf,
            });
        }

        if managed_paths_present {
            return Err(
                "opensnitch-rs managed pin paths are present; refusing legacy direct ringbuf autodiscovery"
                    .to_string(),
            );
        }

        let Some(map_id) = Self::discover_loaded_ringbuf_map_id() else {
            return Err(format!(
                "no opensnitch ringbuf map found (checked pinned: {}; loaded map scan: none)",
                describe_map_candidates(map_paths)
            ));
        };

        let map_data = aya::maps::MapData::from_id(map_id)
            .map_err(|err| format!("open loaded ringbuf map by id failed (id={map_id}): {err}"))?;

        let map = aya::maps::Map::RingBuf(map_data);
        let ringbuf = aya::maps::RingBuf::try_from(map)
            .map_err(|err| format!("attach aya ringbuf reader failed (id={map_id}): {err}"))?;

        Ok(Self {
            source: format!("id={map_id}"),
            ringbuf,
        })
    }

    fn discover_loaded_ringbuf_map_id() -> Option<u32> {
        select_opensnitch_ringbuf_map_id(aya::maps::loaded_maps().flatten().filter_map(|info| {
            let map_type = info.map_type().ok()?;
            Some(RingbufMapCandidate {
                id: info.id(),
                is_ringbuf: map_type == aya::maps::MapType::RingBuf,
                name_matches: info.name_as_str() == Some(EVENTS_MAP_NAME),
                max_entries: info.max_entries(),
            })
        }))
    }

    fn poll_samples(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        // SAFETY: fd originates from Aya ringbuf map and remains valid while self.ringbuf lives.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(self.ringbuf.as_raw_fd()) };
        let mut pfd = [PollFd::new(&borrowed_fd, PollFlags::IN)];
        let timeout_ts = Timespec::try_from(timeout).ok();
        let poll_rc = poll(&mut pfd, timeout_ts.as_ref())
            .map_err(|err| format!("aya ringbuf poll failed ({}): {err}", self.source))?;

        if !aya_poll_has_readable_samples(poll_rc, pfd[0].revents()) {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(64);
        while let Some(item) = self.ringbuf.next() {
            out.push(item.to_vec());
        }

        Ok(out)
    }
}

// Supervisor internals are fully exercised in aya-enabled profiles.
#![cfg(feature = "aya-ebpf")]

use super::*;

#[derive(Debug, Default)]
pub(crate) struct SupervisorState {
    seen_hits: HashMap<(u32, u32, u32), Instant>,
    pressure_maps: HashSet<u32>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EbpfMapPrunePolicy {
    enabled: bool,
    threshold_percent: usize,
    target_percent: usize,
}

impl EbpfMapPrunePolicy {
    pub(super) fn from_tunables(t: RuntimeTunables) -> Self {
        Self {
            enabled: t.ebpf_map_prune_enabled,
            threshold_percent: t.ebpf_map_prune_threshold_percent,
            target_percent: t.ebpf_map_prune_target_percent,
        }
    }
}

impl EbpfWorkerControl {
    pub(super) fn supervise_runtime(
        bus: &Bus,
        state: &mut SupervisorState,
        prune_policy: EbpfMapPrunePolicy,
    ) {
        Self::prune_seen_hits(state);

        #[cfg(not(feature = "aya-ebpf"))]
        let _ = (bus, prune_policy);

        #[cfg(feature = "aya-ebpf")]
        Self::supervise_runtime_aya(bus, state, prune_policy);
    }

    /// Aya-native supervisor: enumerates loaded kernel programs/maps via the BPF syscall
    /// iterators (no bpftool subprocess required) and performs typed map prune + hit events.
    #[cfg(feature = "aya-ebpf")]
    pub(super) fn supervise_runtime_aya(
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

            let bpf_map_meta = RawBpfMap {
                id: map_id,
                name: map_name.clone(),
                max_entries: *max_entries,
            };
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
                            note: format!("eBPF map '{}' (id={map_id}) lookup hit", map_name),
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
    pub(super) fn aya_inspect_and_prune_map<const N: usize>(
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
            let threshold_count = ((max_entries as usize * policy.threshold_percent) + 99) / 100;
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

    pub(super) fn maybe_emit_pressure(
        bus: &Bus,
        state: &mut SupervisorState,
        map: &RawBpfMap,
        entries: u32,
    ) {
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

    pub(super) fn prune_seen_hits(state: &mut SupervisorState) {
        let ttl = Duration::from_secs(5 * 60);
        state.seen_hits.retain(|_, seen_at| seen_at.elapsed() < ttl);
        trace!(seen_hits = state.seen_hits.len(), "pruned eBPF hit cache");
    }
}

#[cfg(feature = "native-ebpf-ringbuf")]
pub(crate) struct NativeRingbuf {
    consumer: EbpfRingbufConsumer,
    dns_deduper: DnsEbpfEventDeduper,
    mode: EbpfWorkerMode,
}

#[cfg(feature = "native-ebpf-ringbuf")]
pub(crate) enum NativeQueuedEvent {
    MapHit { pid: u32, uid: u32, note: String },
    ProcStateChanged(EbpfProcStatePayload),
    DnsUpdate(DnsPayload),
}

impl EbpfWorkerControl {
    #[cfg(feature = "native-ebpf-ringbuf")]
    pub(super) fn parse_native_sample(sample: &[u8]) -> Option<NativeQueuedEvent> {
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
    pub(super) fn parse_exec_sample(sample: &[u8]) -> Option<NativeQueuedEvent> {
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
    pub(super) fn parse_dns_sample(sample: &[u8]) -> Option<DnsPayload> {
        DnsService::parse_ebpf_dns_sample(sample)
    }
}

#[cfg(test)]
#[path = "../../../tests/workers/ebpf_control.rs"]
mod tests;

#[cfg(feature = "native-ebpf-ringbuf")]
impl NativeRingbuf {
    pub(super) fn try_open(
        mode: EbpfWorkerMode,
        worker_name: &'static str,
        pin_domain: EbpfPinDomain,
        #[cfg(feature = "aya-ebpf")] managed_aya_ringbuf: Option<
            crate::services::ebpf::AyaManagedRingbufAsset,
        >,
    ) -> Result<(Self, Vec<String>), String> {
        let managed_candidates =
            pin_domain.native_ringbuf_candidates(mode.enable_proc, mode.enable_dns);
        let legacy_candidates =
            EbpfPinDomain::Legacy.native_ringbuf_candidates(mode.enable_proc, mode.enable_dns);

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

    pub(super) fn poll_and_emit(&mut self, bus: &Bus) -> Result<(), String> {
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

    pub(super) fn backend_kind(&self) -> &crate::services::ebpf::EbpfRingbufBackendKind {
        self.consumer.backend_kind()
    }

    pub(super) fn runtime_mode(&self) -> crate::services::ebpf::EbpfRuntimeMode {
        self.consumer.runtime_mode()
    }

    pub(super) fn should_emit_dns_event(&mut self, payload: &DnsPayload) -> bool {
        self.dns_deduper.should_emit(payload)
    }

    // Retained for profile-specific DNS emit diagnostics/probe paths.
    #[allow(dead_code)]
    pub(super) fn should_emit_dns_event_at(
        recent_events: &mut HashMap<DnsDedupKey, Instant>,
        key: DnsDedupKey,
        now: Instant,
    ) -> bool {
        DnsEbpfEventDeduper::should_emit_at(recent_events, key, now)
    }
}

#[cfg(not(feature = "native-ebpf-ringbuf"))]
pub(crate) struct NativeRingbuf;

#[cfg(not(feature = "native-ebpf-ringbuf"))]
impl NativeRingbuf {
    pub(super) fn try_open(
        _mode: EbpfWorkerMode,
        _worker_name: &'static str,
        _pin_domain: EbpfPinDomain,
        #[cfg(feature = "aya-ebpf")] _managed_aya_ringbuf: Option<
            crate::services::ebpf::AyaManagedRingbufAsset,
        >,
    ) -> Result<(Self, Vec<String>), String> {
        Err("native-ebpf-ringbuf feature disabled".to_string())
    }

    pub(super) fn poll_and_emit(&mut self, _bus: &Bus) -> Result<(), String> {
        Ok(())
    }

    pub(super) fn backend_kind(&self) -> &crate::services::ebpf::EbpfRingbufBackendKind {
        unreachable!("native-ebpf-ringbuf disabled")
    }

    pub(super) fn runtime_mode(&self) -> crate::services::ebpf::EbpfRuntimeMode {
        crate::services::ebpf::EbpfRuntimeMode::UserspaceFallback
    }
}

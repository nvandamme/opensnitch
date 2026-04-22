use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};

use transport_wire_core::WireEvent;

use crate::utils::ring_buffer::RingBuffer;

const fn default_stats_event_ring_capacity() -> usize {
    if cfg!(test) { 64 } else { 250 }
}

const DEFAULT_STATS_EVENT_RING_CAPACITY: usize = default_stats_event_ring_capacity();
pub(super) static STATS_EVENT_RING_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_STATS_EVENT_RING_CAPACITY);

#[repr(align(64))]
pub(super) struct CacheAlignedAtomicU64(pub(super) AtomicU64);

impl Default for CacheAlignedAtomicU64 {
    fn default() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl CacheAlignedAtomicU64 {
    pub(super) fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub(super) fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }
}

#[derive(Default)]
pub(super) struct StatsCounters {
    pub(super) dns_responses: CacheAlignedAtomicU64,
    pub(super) connections: CacheAlignedAtomicU64,
    pub(super) ignored: CacheAlignedAtomicU64,
    pub(super) accepted: CacheAlignedAtomicU64,
    pub(super) dropped: CacheAlignedAtomicU64,
    pub(super) rule_hits: CacheAlignedAtomicU64,
    pub(super) rule_misses: CacheAlignedAtomicU64,
    pub(super) storage_reads: CacheAlignedAtomicU64,
    pub(super) storage_writes: CacheAlignedAtomicU64,
    pub(super) storage_deletes: CacheAlignedAtomicU64,
    pub(super) storage_scans: CacheAlignedAtomicU64,
    pub(super) dropped_events_contention: CacheAlignedAtomicU64,
}

/// Breakdown counters: top-N entries per connection attribute.
///
/// Protected by its own mutex so [`StatsService::on_connect_attempt`] and
/// [`StatsService::on_connection_metadata`] do not contend with the events ring.
pub(super) struct BreakdownCounters {
    pub(super) by_proto: LimitedCountersString,
    pub(super) by_address: LimitedCountersCopy<IpAddr>,
    pub(super) by_host: LimitedCountersString,
    pub(super) by_port: LimitedCountersCopy<u16>,
    pub(super) by_uid: LimitedCountersCopy<u32>,
    pub(super) by_executable: LimitedCountersString,
    pub(super) by_rule: LimitedCountersString,
    pub(super) max_stats: usize,
}

impl Default for BreakdownCounters {
    fn default() -> Self {
        Self {
            by_proto: LimitedCountersString::default(),
            by_address: LimitedCountersCopy::default(),
            by_host: LimitedCountersString::default(),
            by_port: LimitedCountersCopy::default(),
            by_uid: LimitedCountersCopy::default(),
            by_executable: LimitedCountersString::default(),
            by_rule: LimitedCountersString::default(),
            max_stats: 25,
        }
    }
}

/// Events ring buffer and associated metadata.
///
/// Protected by its own mutex so [`StatsService::on_event`] does not contend
/// with breakdown counter updates.
pub(super) struct EventsState {
    pub(super) started_at: Option<Instant>,
    pub(super) events: RingBuffer<WireEvent>,
    pub(super) max_events: usize,
    pub(super) workers: usize,
}

impl Default for EventsState {
    fn default() -> Self {
        let max_events = STATS_EVENT_RING_CAPACITY.load(Ordering::Relaxed).max(1);
        Self {
            started_at: Some(Instant::now()),
            events: RingBuffer::new(max_events),
            max_events,
            workers: 6,
        }
    }
}

#[derive(Default)]
pub(super) struct LimitedCountersString {
    pub(super) map: HashMap<String, u64>,
    pub(super) min_key: Option<String>,
    pub(super) min_dirty: bool,
}

impl LimitedCountersString {
    pub(super) fn bump(&mut self, key: &str, max_stats: usize) {
        if max_stats == 0 {
            return;
        }

        if let Some(value) = self.map.get_mut(key) {
            *value += 1;
            if self.min_key.as_deref() == Some(key) {
                self.min_dirty = true;
            }
            return;
        }

        if self.map.len() >= max_stats {
            self.evict_min();
        }

        let owned = key.to_string();
        self.map.insert(owned.clone(), 1);
        self.min_key = Some(owned);
        self.min_dirty = false;
    }

    pub(super) fn trim_to_limit(&mut self, max_stats: usize) {
        while self.map.len() > max_stats {
            self.evict_min();
        }
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
        } else {
            self.recompute_min();
        }
    }

    fn evict_min(&mut self) {
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
            return;
        }

        if self
            .min_key
            .as_ref()
            .is_none_or(|key| !self.map.contains_key(key))
            || self.min_dirty
        {
            self.recompute_min();
        }

        if let Some(min_key) = self.min_key.take() {
            self.map.remove(&min_key);
        }
        self.min_dirty = true;
    }

    fn recompute_min(&mut self) {
        if let Some((key, _count)) = self.map.iter().min_by_key(|(_, count)| *count) {
            self.min_key = Some(key.clone());
            self.min_dirty = false;
        } else {
            self.min_key = None;
            self.min_dirty = false;
        }
    }
}

pub(super) struct LimitedCountersCopy<K> {
    pub(super) map: HashMap<K, u64>,
    min_key: Option<K>,
    min_dirty: bool,
}

impl<K> Default for LimitedCountersCopy<K> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            min_key: None,
            min_dirty: false,
        }
    }
}

impl<K> LimitedCountersCopy<K>
where
    K: Copy + Eq + Hash,
{
    pub(super) fn bump(&mut self, key: K, max_stats: usize) {
        if max_stats == 0 {
            return;
        }

        if let Some(value) = self.map.get_mut(&key) {
            *value += 1;
            if self.min_key == Some(key) {
                self.min_dirty = true;
            }
            return;
        }

        if self.map.len() >= max_stats {
            self.evict_min();
        }

        self.map.insert(key, 1);
        self.min_key = Some(key);
        self.min_dirty = false;
    }

    pub(super) fn trim_to_limit(&mut self, max_stats: usize) {
        while self.map.len() > max_stats {
            self.evict_min();
        }
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
        } else {
            self.recompute_min();
        }
    }

    fn evict_min(&mut self) {
        if self.map.is_empty() {
            self.min_key = None;
            self.min_dirty = false;
            return;
        }

        if self.min_key.is_none_or(|key| !self.map.contains_key(&key)) || self.min_dirty {
            self.recompute_min();
        }

        if let Some(min_key) = self.min_key.take() {
            self.map.remove(&min_key);
        }
        self.min_dirty = true;
    }

    fn recompute_min(&mut self) {
        if let Some((key, _count)) = self.map.iter().min_by_key(|(_, count)| *count) {
            self.min_key = Some(*key);
            self.min_dirty = false;
        } else {
            self.min_key = None;
            self.min_dirty = false;
        }
    }
}

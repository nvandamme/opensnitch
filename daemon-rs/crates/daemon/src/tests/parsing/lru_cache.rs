//! Tests for [`ConcurrentLruCache`] and the public type aliases.
//!
//! All tests exercise the API through the same types used by production code
//! (`DualLayerLruMap`, `SyncDualLayerLruMap`, and `ConcurrentLruCache`).

use quick_cache::Weighter;

use crate::utils::lru_cache::{
    ConcurrentLruCache, DualLayerLruMap, SyncDualLayerLruMap, global_dual_layer_metrics_snapshot,
};

#[test]
fn dual_layer_insert_and_get() {
    let cache: DualLayerLruMap<String, u32> = DualLayerLruMap::new(8);
    cache.insert("a".to_string(), 1);
    cache.insert("b".to_string(), 2);
    assert_eq!(cache.get("a"), Some(1));
    assert_eq!(cache.get("b"), Some(2));
    assert_eq!(cache.get("c"), None);
}

#[test]
fn dual_layer_remove_removes_entry() {
    let cache: DualLayerLruMap<String, u32> = DualLayerLruMap::new(8);
    cache.insert("x".to_string(), 42);
    assert_eq!(cache.remove_by("x"), Some(42));
    assert_eq!(cache.get("x"), None);
}

#[test]
fn dual_layer_clear_empties() {
    let cache: DualLayerLruMap<String, u32> = DualLayerLruMap::new(8);
    for i in 0..4 {
        cache.insert(format!("k{i}"), i as u32);
    }
    cache.clear();
    assert_eq!(cache.len(), 0);
}

#[test]
fn dual_layer_insert_many() {
    let cache: DualLayerLruMap<String, u32> = DualLayerLruMap::new(64);
    cache.insert_many((0..8).map(|i| (format!("k{i}"), i as u32)));
    assert_eq!(cache.len(), 8);
    assert_eq!(cache.get("k0"), Some(0));
    assert_eq!(cache.get("k7"), Some(7));
}

#[test]
fn dual_layer_evicts_over_capacity() {
    let capacity = 8_usize;
    let cache: DualLayerLruMap<u32, u32> = DualLayerLruMap::new(capacity);
    for i in 0..(capacity * 4) as u32 {
        cache.insert(i, i);
    }
    assert!(cache.len() <= capacity);
}

#[test]
fn sync_dual_layer_insert_and_get() {
    let cache: SyncDualLayerLruMap<u32, u32> = SyncDualLayerLruMap::new(8);
    cache.insert(1, 100);
    cache.insert(2, 200);
    assert_eq!(cache.get(&1), Some(100));
    assert_eq!(cache.get(&99), None);
}

#[test]
fn sync_dual_layer_set_capacity_evicts() {
    let cache: SyncDualLayerLruMap<u32, u32> = SyncDualLayerLruMap::new(64);
    for i in 0..32_u32 {
        cache.insert(i, i);
    }
    assert_eq!(cache.len(), 32);
    cache.set_capacity(8);
    assert!(cache.len() <= 8);
}

#[test]
fn peek_does_not_affect_recency() {
    // peek() should return the value without side-effects on eviction order.
    let cache: ConcurrentLruCache<u32, u32> = ConcurrentLruCache::new(4);
    cache.insert(1, 10);
    cache.insert(2, 20);
    assert_eq!(cache.peek(&1), Some(10));
    assert_eq!(cache.peek(&99), None);
    // Value is still present after peek.
    assert_eq!(cache.get(&1), Some(10));
}

#[test]
fn global_metrics_count_hits_and_misses() {
    let before = global_dual_layer_metrics_snapshot();
    let cache: ConcurrentLruCache<String, u32> = ConcurrentLruCache::new(8);
    cache.insert("x".to_string(), 42);
    let _ = cache.get("x"); // hit
    let _ = cache.get("absent"); // miss
    let after = global_dual_layer_metrics_snapshot();
    let delta = after.saturating_delta(before);
    assert!(delta.hits >= 1);
    assert!(delta.misses >= 1);
    assert_eq!(delta.total(), delta.hits + delta.misses);
}

// ---------------------------------------------------------------------------
// with_weighter tests
// ---------------------------------------------------------------------------

/// A weighter that assigns weight equal to the value's byte length.
/// This allows the cache to cap by total bytes rather than item count.
#[derive(Clone, Copy, Default)]
struct ByteWeighter;

impl Weighter<u32, Vec<u8>> for ByteWeighter {
    fn weight(&self, _key: &u32, val: &Vec<u8>) -> u64 {
        val.len().max(1) as u64
    }
}

#[test]
fn with_weighter_respects_byte_budget() {
    // Budget = 16 bytes; each entry is 8 bytes → at most 2 fit.
    let capacity: u64 = 16;
    let cache: ConcurrentLruCache<u32, Vec<u8>, ByteWeighter> =
        ConcurrentLruCache::with_weighter(capacity, 4, ByteWeighter);

    cache.insert(0, vec![0u8; 8]);
    cache.insert(1, vec![0u8; 8]);
    cache.insert(2, vec![0u8; 8]); // pushes total weight to 24 → triggers eviction

    // After eviction, no more than `capacity / 8` entries should remain.
    assert!(
        cache.len() <= (capacity as usize / 8),
        "expected at most {} entries, got {}",
        capacity / 8,
        cache.len(),
    );
}

#[test]
fn with_weighter_stores_and_retrieves_entries() {
    let cache: ConcurrentLruCache<u32, Vec<u8>, ByteWeighter> =
        ConcurrentLruCache::with_weighter(1024, 16, ByteWeighter);
    cache.insert(1, vec![0xABu8; 10]);
    cache.insert(2, vec![0xCDu8; 5]);
    assert_eq!(cache.get(&1), Some(vec![0xABu8; 10]));
    assert_eq!(cache.get(&2), Some(vec![0xCDu8; 5]));
    assert_eq!(cache.get(&99), None);
}

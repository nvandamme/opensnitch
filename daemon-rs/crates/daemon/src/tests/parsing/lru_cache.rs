use std::time::Duration;

use crate::utils::lru_cache::{DualLayerLruMap, LruCache, global_dual_layer_metrics_snapshot};

#[derive(Debug, Clone, Copy)]
struct WorkloadReport {
    publish_full: u64,
    publish_incremental: u64,
    publish_reconcile_scans: u64,
    publish_reconcile_removed: u64,
    touch_enqueued: u64,
    touch_reconciled_keys: u64,
}

async fn run_read_write_workload(
    capacity: usize,
    key_space: usize,
    writes: usize,
    reads_per_write: usize,
) -> WorkloadReport {
    let cache = DualLayerLruMap::new(capacity);
    for idx in 0..writes {
        let write_key = format!("k{}", idx % key_space);
        cache.insert(write_key.clone(), idx as u32).await;

        // Synthetic read-heavy profile: repeatedly read hot/recent keys so
        // touch-pressure signals stay stable across environments.
        for _ in 0..reads_per_write {
            let _ = cache.get(&write_key);
        }
    }

    tokio::time::sleep(Duration::from_millis(25)).await;
    let metrics = cache.metrics_snapshot();
    WorkloadReport {
        publish_full: metrics.publish_full,
        publish_incremental: metrics.publish_incremental,
        publish_reconcile_scans: metrics.publish_reconcile_scans,
        publish_reconcile_removed: metrics.publish_reconcile_removed,
        touch_enqueued: metrics.touch_enqueued,
        touch_reconciled_keys: metrics.touch_reconciled_keys,
    }
}

async fn run_batched_write_workload(
    capacity: usize,
    key_space: usize,
    batches: usize,
    batch_size: usize,
) -> WorkloadReport {
    let cache = DualLayerLruMap::new(capacity);
    for batch in 0..batches {
        let entries = (0..batch_size).map(|offset| {
            let idx = batch * batch_size + offset;
            (format!("k{}", idx % key_space), idx as u32)
        });
        cache.insert_many(entries).await;
    }

    tokio::time::sleep(Duration::from_millis(25)).await;
    let metrics = cache.metrics_snapshot();
    WorkloadReport {
        publish_full: metrics.publish_full,
        publish_incremental: metrics.publish_incremental,
        publish_reconcile_scans: metrics.publish_reconcile_scans,
        publish_reconcile_removed: metrics.publish_reconcile_removed,
        touch_enqueued: metrics.touch_enqueued,
        touch_reconciled_keys: metrics.touch_reconciled_keys,
    }
}

#[test]
fn evicts_least_recently_used_entry() {
    let mut cache = LruCache::new(2);
    cache.insert("a".to_string(), 1_u32);
    cache.insert("b".to_string(), 2_u32);

    // Touch "a" so "b" becomes the next eviction candidate.
    assert_eq!(cache.get_by("a"), Some(&1));

    cache.insert("c".to_string(), 3_u32);

    assert_eq!(cache.get_by("a"), Some(&1));
    assert_eq!(cache.get_by("b"), None);
    assert_eq!(cache.get_by("c"), Some(&3));
}

#[tokio::test]
async fn dual_layer_touch_reconciler_keeps_touched_entry_hot() {
    let cache = DualLayerLruMap::new(2);
    cache.insert("a".to_string(), 1_u32).await;
    cache.insert("b".to_string(), 2_u32).await;

    let a = "a".to_string();
    assert_eq!(cache.get(&a), Some(1_u32));

    // The touch reconciler runs asynchronously; give it a short scheduling window
    // before inserting the next entry and triggering eviction.
    tokio::time::sleep(Duration::from_millis(20)).await;
    cache.insert("c".to_string(), 3_u32).await;

    let snapshot = cache.get_snapshot();
    assert_eq!(snapshot.get("a"), Some(&1_u32));
    assert_eq!(snapshot.get("b"), None);
    assert_eq!(snapshot.get("c"), Some(&3_u32));
}

#[tokio::test]
async fn dual_layer_mutations_refresh_snapshot() {
    let cache = DualLayerLruMap::new(2);
    cache.insert("a".to_string(), 1_u32).await;
    cache.insert("b".to_string(), 2_u32).await;

    assert_eq!(cache.remove_by("a").await, Some(1_u32));
    let snapshot = cache.get_snapshot();
    assert_eq!(snapshot.get("a"), None);
    assert_eq!(snapshot.get("b"), Some(&2_u32));

    cache.clear().await;
    assert!(cache.get_snapshot().is_empty());
}

#[tokio::test]
async fn dual_layer_incremental_publish_reconciles_eviction() {
    let cache = DualLayerLruMap::new(2);
    cache.insert("a".to_string(), 1_u32).await;
    cache.insert("b".to_string(), 2_u32).await;
    cache.insert("c".to_string(), 3_u32).await;

    let snapshot = cache.get_snapshot();
    assert_eq!(snapshot.get("a"), None);
    assert_eq!(snapshot.get("b"), Some(&2_u32));
    assert_eq!(snapshot.get("c"), Some(&3_u32));

    let metrics = cache.metrics_snapshot();
    assert_eq!(metrics.publish_full, 0);
    assert!(metrics.publish_incremental >= 3);
    assert!(metrics.publish_reconcile_scans >= 1);
    assert!(metrics.publish_reconcile_removed >= 1);
}

#[tokio::test]
async fn dual_layer_metrics_capture_touch_enqueue() {
    let cache = DualLayerLruMap::new(4);
    cache.insert("a".to_string(), 1_u32).await;
    cache.insert("b".to_string(), 2_u32).await;

    let a = "a".to_string();
    assert_eq!(cache.get(&a), Some(1_u32));

    tokio::time::sleep(Duration::from_millis(20)).await;
    let metrics = cache.metrics_snapshot();
    assert!(metrics.touch_enqueued >= 1);
    assert!(metrics.publish_total_ns > 0);
}

#[tokio::test]
async fn dual_layer_insert_many_small_batch_prefers_incremental_publish() {
    let cache = DualLayerLruMap::new(128);
    cache
        .insert_many((0..8).map(|idx| (format!("k{idx}"), idx as u32)))
        .await;

    let snapshot = cache.get_snapshot();
    assert_eq!(snapshot.len(), 8);
    assert_eq!(snapshot.get("k0"), Some(&0_u32));
    assert_eq!(snapshot.get("k7"), Some(&7_u32));

    let metrics = cache.metrics_snapshot();
    assert!(metrics.publish_incremental >= 1);
    assert_eq!(metrics.publish_full, 0);
}

#[tokio::test]
async fn dual_layer_insert_many_large_batch_falls_back_to_full_publish() {
    let cache = DualLayerLruMap::new(256);
    cache
        .insert_many((0..96).map(|idx| (format!("k{idx}"), idx as u32)))
        .await;

    let snapshot = cache.get_snapshot();
    assert_eq!(snapshot.len(), 96);
    assert_eq!(snapshot.get("k0"), Some(&0_u32));
    assert_eq!(snapshot.get("k95"), Some(&95_u32));

    let metrics = cache.metrics_snapshot();
    assert!(metrics.publish_full >= 1);
}

#[tokio::test]
async fn dual_layer_global_metrics_are_exported() {
    let before = global_dual_layer_metrics_snapshot();
    let cache = DualLayerLruMap::new(8);
    cache.insert("a".to_string(), 1_u32).await;
    let after = global_dual_layer_metrics_snapshot();
    let delta = after.saturating_delta(before);
    assert!(delta.publish_incremental >= 1);
}

#[tokio::test]
async fn synthetic_harness_read_heavy_reports_touch_dominance() {
    let report = run_read_write_workload(256, 512, 600, 8).await;
    assert!(report.publish_incremental >= 500);
    assert_eq!(report.publish_full, 0);
    assert!(report.touch_enqueued > report.publish_incremental);
    assert!(report.touch_reconciled_keys > 0);
}

#[tokio::test]
async fn synthetic_harness_write_heavy_batched_reports_publish_pressure() {
    let report = run_batched_write_workload(512, 4096, 24, 96).await;
    assert!(report.publish_full >= 20);
    assert_eq!(report.touch_enqueued, 0);
    assert_eq!(report.touch_reconciled_keys, 0);
}

#[tokio::test]
#[ignore = "manual synthetic harness for trend collection"]
async fn synthetic_harness_manual_trend_snapshot() {
    let read_heavy = run_read_write_workload(512, 2048, 2_000, 12).await;
    let write_heavy = run_batched_write_workload(1_024, 65_536, 80, 128).await;

    eprintln!("synthetic-read-heavy={read_heavy:?}");
    eprintln!("synthetic-write-heavy={write_heavy:?}");

    assert!(read_heavy.touch_enqueued > 0);
    assert!(write_heavy.publish_full > 0);
    assert!(read_heavy.publish_reconcile_scans + write_heavy.publish_reconcile_scans > 0);
    assert!(read_heavy.publish_reconcile_removed + write_heavy.publish_reconcile_removed > 0);
}

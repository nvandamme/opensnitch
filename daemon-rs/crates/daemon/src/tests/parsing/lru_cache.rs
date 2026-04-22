use std::time::Duration;

use crate::utils::lru_cache::{DualLayerLruMap, LruCache};

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

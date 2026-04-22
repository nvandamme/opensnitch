use crate::services::subscription::storage::SubscriptionStorage;
use crate::tests::support::{TestDir, read_text, write_bytes};
use crate::utils::atomic_write::sibling_temp_path_with_suffix;
use transport_wire_core::WireSubscription;

fn unique_store_path(dir: &TestDir) -> std::path::PathBuf {
    dir.path.join("subscriptions.json")
}

#[test]
fn flush_is_atomic_and_survives_reload() {
    let dir = TestDir::new("opensnitch-sub-store-flush");
    let path = unique_store_path(&dir);

    let storage = SubscriptionStorage::new(&path).expect("create store");
    storage.apply(vec![WireSubscription {
        name: "test-sub".to_string(),
        url: "https://example.com/list.txt".to_string(),
        enabled: true,
        ..Default::default()
    }]);
    storage.flush().expect("flush");

    assert!(path.exists(), "store file must exist after flush");
    assert!(
        !sibling_temp_path_with_suffix(&path, ".tmp").exists(),
        "temp file must be cleaned up after flush"
    );

    let storage2 = SubscriptionStorage::new(&path).expect("reload store");
    let items = storage2.list();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "test-sub");
}

#[test]
fn flush_is_idempotent_when_not_dirty() {
    let dir = TestDir::new("opensnitch-sub-store-idempotent");
    let path = unique_store_path(&dir);
    let storage = SubscriptionStorage::new(&path).expect("create store");
    // No mutations -> flush is a no-op, no file created.
    storage.flush().expect("flush no-op");
    assert!(
        !path.exists(),
        "no file should be created for a clean store"
    );
}

#[test]
fn stale_tmp_is_removed_before_flush() {
    let dir = TestDir::new("opensnitch-sub-store-stale-tmp");
    let path = unique_store_path(&dir);
    let tmp_path = sibling_temp_path_with_suffix(&path, ".tmp");

    // Plant a stale temp file to simulate a previous interrupted flush.
    write_bytes(&tmp_path, b"stale");

    let storage = SubscriptionStorage::new(&path).expect("create store");
    storage.apply(vec![WireSubscription {
        name: "sub-a".to_string(),
        url: "https://a.example.com/list.txt".to_string(),
        enabled: true,
        ..Default::default()
    }]);
    storage.flush().expect("flush with stale tmp present");

    let content = read_text(&path);
    assert!(
        content.contains("sub-a"),
        "store must hold applied subscription"
    );
    assert!(!tmp_path.exists(), "stale tmp must be removed");
}

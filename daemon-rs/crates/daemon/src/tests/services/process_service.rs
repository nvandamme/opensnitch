use crate::platform::procmon::proc_event::ProcEventKind;
use crate::services::process::ProcessService;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn inspect_unknown_pid_returns_error() {
    let service = ProcessService::default();
    let result = service.inspect(u32::MAX).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn exit_event_does_not_make_inspect_succeed_for_unknown_pid() {
    let service = ProcessService::default();
    let _ = service.sync_from_proc_event(0, ProcEventKind::Exit).await;
    let result = service.inspect(0).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn exec_event_warms_cache_for_running_process() {
    let service = ProcessService::default();
    let pid = std::process::id();

    service
        .sync_from_proc_event(pid, ProcEventKind::Exec)
        .await
        .expect("sync exec event for running process");
    let info = service
        .inspect(pid)
        .await
        .expect("inspect running pid after exec");

    assert_eq!(info.pid, pid);
    assert!(!info.path.is_empty());
}

#[tokio::test]
async fn inspect_running_process_is_consistent_across_calls() {
    let service = ProcessService::default();
    let pid = std::process::id();

    let first = service.inspect(pid).await.expect("first inspect");
    let second = service.inspect(pid).await.expect("second inspect");

    assert_eq!(first.pid, second.pid);
    assert_eq!(first.path, second.path);
}

#[tokio::test]
async fn inspect_running_process_exposes_basic_proc_fields() {
    let service = ProcessService::default();
    let pid = std::process::id();

    let info = service
        .inspect(pid)
        .await
        .expect("inspect running pid for proc fields");

    assert_eq!(info.pid, pid);
    assert!(!info.path.is_empty());
    assert!(!info.args.is_empty());
    assert!(info.cwd.as_deref().is_some_and(|cwd| !cwd.is_empty()));
    assert!(!info.parent_chain.is_empty());
    assert_eq!(info.parent_chain[0].pid, pid);
}

#[tokio::test]
async fn inspect_running_process_hash_is_stable_when_available() {
    let service = ProcessService::default();
    let pid = std::process::id();

    let first = service.inspect(pid).await.expect("first inspect");
    let second = service.inspect(pid).await.expect("second inspect");

    match (&first.process_hash, &second.process_hash) {
        (Some(a), Some(b)) => {
            assert_eq!(a, b);
            assert_eq!(a.len(), 64);
            assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
        _ => {
            assert!(first.process_hash.is_none());
            assert!(second.process_hash.is_none());
        }
    }
}

#[tokio::test]
async fn exec_after_exit_rehydrates_cache_entry() {
    let service = ProcessService::default();
    let pid = std::process::id();

    service
        .sync_from_proc_event(pid, ProcEventKind::Exit)
        .await
        .expect("sync exit event before cache refresh");
    service
        .sync_from_proc_event(pid, ProcEventKind::Exec)
        .await
        .expect("sync exec event after cache refresh");

    let info = service
        .inspect(pid)
        .await
        .expect("exec after exit should refresh cache entry");

    assert_eq!(info.pid, pid);
    assert!(!info.path.is_empty());
}

#[tokio::test]
async fn inspect_running_process_parent_chain_is_bounded() {
    let service = ProcessService::default();
    let pid = std::process::id();

    let info = service.inspect(pid).await.expect("inspect running pid");

    assert!(!info.parent_chain.is_empty());
    assert!(info.parent_chain.len() <= 64);
    assert_eq!(info.parent_chain[0].pid, pid);
}

#[tokio::test]
async fn fork_after_exit_rehydrates_cache_entry() {
    let service = ProcessService::default();
    let pid = std::process::id();

    service
        .sync_from_proc_event(pid, ProcEventKind::Exit)
        .await
        .expect("sync exit event before fork refresh");
    service
        .sync_from_proc_event(pid, ProcEventKind::Fork)
        .await
        .expect("sync fork event after exit refresh");

    let info = service
        .inspect(pid)
        .await
        .expect("fork after exit should refresh cache entry");

    assert_eq!(info.pid, pid);
    assert!(!info.path.is_empty());
}

#[tokio::test]
async fn inspect_running_process_parent_chain_paths_are_not_empty() {
    let service = ProcessService::default();
    let pid = std::process::id();

    let info = service.inspect(pid).await.expect("inspect running pid");
    assert!(!info.parent_chain.is_empty());
    assert!(
        info.parent_chain
            .iter()
            .all(|node| !node.path.trim().is_empty())
    );
}

#[tokio::test]
async fn fork_event_warms_cache_for_running_process() {
    let service = ProcessService::default();
    let pid = std::process::id();

    service
        .sync_from_proc_event(pid, ProcEventKind::Fork)
        .await
        .expect("sync fork event for running process");
    let info = service
        .inspect(pid)
        .await
        .expect("inspect running pid after fork");

    assert_eq!(info.pid, pid);
    assert!(!info.path.is_empty());
}

#[tokio::test]
async fn exit_after_exec_keeps_recent_cached_entry_until_ttl() {
    let service = ProcessService::default();
    let pid = std::process::id();

    service
        .sync_from_proc_event(pid, ProcEventKind::Exec)
        .await
        .expect("sync exec event before exit");
    service
        .sync_from_proc_event(pid, ProcEventKind::Exit)
        .await
        .expect("sync exit event after exec");

    let info = service
        .inspect(pid)
        .await
        .expect("recently exited process should still resolve from cache");

    assert_eq!(info.pid, pid);
}

#[tokio::test]
async fn fork_event_with_invalid_pid_does_not_make_inspect_succeed() {
    let service = ProcessService::default();
    let _ = service.sync_from_proc_event(0, ProcEventKind::Fork).await;

    let result = service.inspect(0).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn cleanup_task_prunes_expired_entries() {
    let service = ProcessService::default();
    service.probe_inject_expired_cache_entry(4242).await;

    let shutdown = CancellationToken::new();
    let handle = service
        .spawn_cleanup_task_with_interval(shutdown.clone(), std::time::Duration::from_millis(10));

    timeout(std::time::Duration::from_secs(1), async {
        loop {
            if service.probe_cache_len().await == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cleanup task should prune expired entries");

    shutdown.cancel();
    let _ = timeout(std::time::Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn process_cache_is_bounded_with_lru_eviction() {
    let service = ProcessService::default();
    let cap = ProcessService::probe_cache_capacity();

    // Insert 2× capacity to guarantee every shard cycles and oldest items are evicted.
    for idx in 0..(cap * 2) {
        service
            .probe_insert_cache_entry_for_pid((10_000 + idx) as u32)
            .await;
    }

    // Cache is bounded (approximate eviction may leave a few slots unused).
    assert!(service.probe_cache_len().await <= cap);
    // Most recently inserted entry is still present.
    assert!(
        service
            .probe_cache_contains_pid((10_000 + cap * 2 - 1) as u32)
            .await
    );
}

// ---------------------------------------------------------------------------
// Persistent hash cache tests
// ---------------------------------------------------------------------------

fn temp_hash_cache_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join("opensnitchd_test_hash_cache")
        .join(tag)
        .join(format!("{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn persistent_hash_cache_insert_and_lookup() {
    let dir = temp_hash_cache_dir("insert_lookup");
    let path = dir.join("hash_cache.bin");
    let cache = crate::services::process::hash_cache::PersistentHashCache::load_or_new(path);

    // Current binary as a real file to stat against.
    let exe = std::env::current_exe().unwrap();
    assert!(cache.get(&exe).is_none(), "cache starts empty");

    cache.insert(&exe, "aaa", "bbb", "ccc");
    let (md5, sha1, sha256) = cache.get(&exe).expect("should hit after insert");
    assert_eq!(md5, "aaa");
    assert_eq!(sha1, "bbb");
    assert_eq!(sha256, "ccc");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persistent_hash_cache_survives_flush_and_reload() {
    let dir = temp_hash_cache_dir("flush_reload");
    let path = dir.join("hash_cache.bin");

    let exe = std::env::current_exe().unwrap();

    // Populate and flush.
    {
        let cache =
            crate::services::process::hash_cache::PersistentHashCache::load_or_new(path.clone());
        cache.insert(&exe, "md5val", "sha1val", "sha256val");
        cache.flush();
    }

    // Reload from disk — entries whose stat still matches should survive.
    {
        let cache = crate::services::process::hash_cache::PersistentHashCache::load_or_new(path);
        let hit = cache.get(&exe);
        assert!(hit.is_some(), "cache should survive reload");
        let (md5, sha1, sha256) = hit.unwrap();
        assert_eq!(md5, "md5val");
        assert_eq!(sha1, "sha1val");
        assert_eq!(sha256, "sha256val");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persistent_hash_cache_invalidates_on_size_change() {
    let dir = temp_hash_cache_dir("invalidate_size");
    let path = dir.join("hash_cache.bin");
    let target = dir.join("fake_binary");

    // Create a file, insert hash, flush.
    std::fs::write(&target, b"hello").unwrap();
    let cache =
        crate::services::process::hash_cache::PersistentHashCache::load_or_new(path.clone());
    cache.insert(&target, "m", "s", "h");
    cache.flush();

    // Modify file (size changes) — simulates a package update.
    std::fs::write(&target, b"hello world, updated binary!").unwrap();

    // Reload: old entry should NOT match (size/mtime differ).
    let cache = crate::services::process::hash_cache::PersistentHashCache::load_or_new(path);
    assert!(
        cache.get(&target).is_none(),
        "stale entry should be invalidated after binary update"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persistent_hash_cache_gc_removes_deleted_files() {
    let dir = temp_hash_cache_dir("gc_deleted");
    let path = dir.join("hash_cache.bin");
    let target = dir.join("ephemeral");

    std::fs::write(&target, b"temp").unwrap();
    let cache = crate::services::process::hash_cache::PersistentHashCache::load_or_new(path);
    cache.insert(&target, "m", "s", "h");
    assert!(cache.get(&target).is_some());

    // Delete file — gc_stale should remove the entry.
    std::fs::remove_file(&target).unwrap();
    cache.gc_stale();
    assert!(
        cache.get(&target).is_none(),
        "gc_stale should remove entries for deleted files"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Persistent file-based cache for process binary checksums (md5/sha1/sha256).
///
/// Survives daemon restarts by serialising to an internal binary snapshot
/// file on disk.
/// Invalidation: keyed on `(path, inode, mtime_secs, file_size)` — any binary
/// change from a package update, recompile, or manual edit automatically
/// invalidates the cached entry because at least one of those metadata fields
/// will differ.
///
/// A background flush task periodically writes dirty state to disk.
/// On startup, entries whose on-disk metadata no longer matches are
/// silently discarded (lazy GC).
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::models::storage::hash_cache::{
    HashCacheEntry, HashCacheKey, InternalHashCacheFile, InternalHashCacheRecord,
};

// ---------------------------------------------------------------------------
// PersistentHashCache
// ---------------------------------------------------------------------------

/// Thread-safe persistent hash cache backed by `DashMap` with periodic disk flush.
pub(crate) struct PersistentHashCache {
    map: DashMap<HashCacheKey, HashCacheEntry>,
    file_path: PathBuf,
    dirty: AtomicBool,
}

impl PersistentHashCache {
    /// Load from `file_path`, discarding any entries whose on-disk metadata
    /// (inode/mtime/size) no longer match the current file.
    pub(crate) fn load_or_new(file_path: PathBuf) -> Self {
        let map = DashMap::new();
        if let Some(cache_file) = read_internal_cache_file(&file_path) {
            for record in cache_file.entries {
                let key = HashCacheKey {
                    path: record.path,
                    inode: record.inode,
                    mtime_secs: record.mtime_secs,
                    size: record.size,
                };
                // Lazy validation: only insert entries whose binary still
                // matches the cached metadata (inode+mtime+size).
                if stat_matches(&key) {
                    let entry = HashCacheEntry {
                        md5: record.md5,
                        sha1: record.sha1,
                        sha256: record.sha256,
                    };
                    map.insert(key, entry);
                }
            }
        }
        tracing::info!(
            "hash cache: loaded {} entries from {}",
            map.len(),
            file_path.display()
        );
        Self {
            map,
            file_path,
            dirty: AtomicBool::new(false),
        }
    }

    /// Look up cached hashes for a binary at `exe_path`.
    ///
    /// Returns `Some((md5, sha1, sha256))` if the binary's current inode, mtime,
    /// and size match a cached entry. Returns `None` on mismatch or absence.
    pub(crate) fn get(&self, exe_path: &Path) -> Option<(String, String, String)> {
        let key = stat_to_key(exe_path)?;
        self.map
            .get(&key)
            .map(|entry| (entry.md5.clone(), entry.sha1.clone(), entry.sha256.clone()))
    }

    /// Insert (or update) cached hashes for the binary at `exe_path`.
    pub(crate) fn insert(&self, exe_path: &Path, md5: &str, sha1: &str, sha256: &str) {
        if let Some(key) = stat_to_key(exe_path) {
            self.map.insert(
                key,
                HashCacheEntry {
                    md5: md5.to_string(),
                    sha1: sha1.to_string(),
                    sha256: sha256.to_string(),
                },
            );
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Flush dirty state to disk (no-op if nothing changed since last flush).
    pub(crate) fn flush(&self) {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let cache_file = InternalHashCacheFile {
            version: 1,
            entries: self
                .map
                .iter()
                .map(|r| {
                    let k = r.key();
                    let v = r.value();
                    InternalHashCacheRecord {
                        path: k.path.clone(),
                        inode: k.inode,
                        mtime_secs: k.mtime_secs,
                        size: k.size,
                        md5: v.md5.clone(),
                        sha1: v.sha1.clone(),
                        sha256: v.sha256.clone(),
                    }
                })
                .collect(),
        };
        if let Some(parent) = self.file_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!("hash cache parent directory create failed: {e}");
            self.dirty.store(true, Ordering::Relaxed);
            return;
        }

        let mut bytes = Vec::with_capacity(HASH_CACHE_MAGIC.len() + 128);
        bytes.extend_from_slice(HASH_CACHE_MAGIC);
        match postcard::to_allocvec(&cache_file) {
            Ok(payload) => bytes.extend_from_slice(&payload),
            Err(e) => {
                tracing::warn!("hash cache serialisation failed: {e}");
                self.dirty.store(true, Ordering::Relaxed);
                return;
            }
        }

        if let Err(e) = atomic_write(&self.file_path, &bytes) {
            tracing::warn!("hash cache flush failed: {e}");
            // Restore dirty flag so we retry next interval.
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Remove entries whose binary metadata no longer matches the filesystem.
    ///
    /// Called periodically to GC entries invalidated by package upgrades that
    /// happened while the daemon was running.
    pub(crate) fn gc_stale(&self) {
        self.map.retain(|key, _| stat_matches(key));
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Spawn background flush + GC task.  Flushes every `flush_interval` and
    /// runs stale-entry GC every `gc_interval`.
    pub(crate) fn spawn_flush_task(
        self: &std::sync::Arc<Self>,
        shutdown: CancellationToken,
        flush_interval: Duration,
        gc_interval: Duration,
    ) -> JoinHandle<()> {
        let cache = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut flush_ticker = tokio::time::interval(flush_interval);
            flush_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut gc_ticker = tokio::time::interval(gc_interval);
            gc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        // Final flush on shutdown.
                        cache.flush();
                        break;
                    }
                    _ = flush_ticker.tick() => cache.flush(),
                    _ = gc_ticker.tick() => {
                        let cache = cache.clone();
                        tokio::task::spawn_blocking(move || cache.gc_stale()).await.ok();
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a cache key from the current filesystem metadata of `exe_path`.
fn stat_to_key(exe_path: &Path) -> Option<HashCacheKey> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(exe_path).ok()?;
    Some(HashCacheKey {
        path: exe_path.to_string_lossy().into_owned(),
        inode: meta.ino(),
        mtime_secs: meta.mtime(),
        size: meta.size(),
    })
}

/// Check whether a cached key still matches the file on disk.
fn stat_matches(key: &HashCacheKey) -> bool {
    stat_to_key(Path::new(&key.path))
        .map(|current| current == *key)
        .unwrap_or(false)
}

fn read_internal_cache_file(path: &Path) -> Option<InternalHashCacheFile> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < HASH_CACHE_MAGIC.len() {
        return None;
    }
    if &bytes[..HASH_CACHE_MAGIC.len()] != HASH_CACHE_MAGIC {
        return None;
    }
    postcard::from_bytes::<InternalHashCacheFile>(&bytes[HASH_CACHE_MAGIC.len()..]).ok()
}

/// Write `data` atomically by writing to a temp file and renaming.
fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default flush interval (60 seconds).
pub(crate) const HASH_CACHE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Default GC interval for stale entries (10 minutes).
/// Covers in-flight package updates while the daemon is running.
pub(crate) const HASH_CACHE_GC_INTERVAL: Duration = Duration::from_secs(600);

/// Default cache file location (alongside daemon config).
pub(crate) const HASH_CACHE_FILENAME: &str = "hash_cache.bin";

// Bumped from OSHASHC1 (bincode) to OSHASHC2 (postcard) to invalidate old caches.
const HASH_CACHE_MAGIC: &[u8] = b"OSHASHC2";

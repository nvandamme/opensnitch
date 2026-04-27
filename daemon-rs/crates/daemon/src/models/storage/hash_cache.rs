/// Data-contract types for the persistent process-hash cache.
///
/// The on-disk representation is an internal binary snapshot (`hash_cache.bin`;
/// OSHASHC1 magic prefix + bincode-encoded payload).  These types are the
/// in-memory key/value types used by `PersistentHashCache`; the binary
/// serialisation contract structs are also kept here to satisfy the
/// model-ownership design rule.
///
/// Keyed on `(path, inode, mtime_secs, file_size)` — any binary change
/// (package update, recompile) automatically invalidates the entry.
use serde::{Deserialize, Serialize};

/// Composite key that uniquely identifies a specific version of an executable.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashCacheKey {
    pub path: String,
    pub inode: u64,
    pub mtime_secs: i64,
    pub size: u64,
}

/// The three precomputed hex-encoded digests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashCacheEntry {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Internal binary snapshot envelope (`hash_cache.bin`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InternalHashCacheFile {
    pub(crate) version: u32,
    pub(crate) entries: Vec<InternalHashCacheRecord>,
}

/// Internal binary snapshot row (`hash_cache.bin`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InternalHashCacheRecord {
    pub(crate) path: String,
    pub(crate) inode: u64,
    pub(crate) mtime_secs: i64,
    pub(crate) size: u64,
    pub(crate) md5: String,
    pub(crate) sha1: String,
    pub(crate) sha256: String,
}

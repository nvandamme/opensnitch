/// Data-contract types for the persistent process-hash cache.
///
/// Serialised to/from JSON on disk (`hash_cache.json`).  Keyed on
/// `(path, inode, mtime_secs, file_size)` — any binary change
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

/// Serialised cache format (version-tagged array of records).
#[derive(Serialize, Deserialize)]
pub struct HashCacheFile {
    pub version: u32,
    pub entries: Vec<HashCacheRecord>,
}

/// A single record in the on-disk JSON file (key fields flattened).
#[derive(Serialize, Deserialize)]
pub struct HashCacheRecord {
    #[serde(flatten)]
    pub key: HashCacheKey,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

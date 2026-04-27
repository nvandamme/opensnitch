use std::collections::HashMap;

use crate::platform::procmon::procfs::{ProcDescriptor, ProcIoStats, ProcStatm};

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub path: String,
    pub comm: Option<String>,
    pub root: String,
    pub uid: Option<u32>,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env_preview: Vec<String>,
    pub env_map: HashMap<String, String>,
    pub process_hash: Option<String>,
    pub process_hash_md5: Option<String>,
    pub process_hash_sha1: Option<String>,
    pub parent_chain: Vec<ProcessNode>,
}

/// Extra runtime information about a process.
/// Go: populated by `Process.GetExtraInfo()` → `readDescriptors`, `readIOStats`, `readStatus`.
#[derive(Debug, Clone, Default)]
pub struct ProcessExtraInfo {
    pub env: HashMap<String, String>,
    pub descriptors: Vec<ProcDescriptor>,
    pub io_stats: Option<ProcIoStats>,
    pub statm: Option<ProcStatm>,
    pub status: String,
    pub stat: String,
    pub stack: String,
    pub maps: String,
}

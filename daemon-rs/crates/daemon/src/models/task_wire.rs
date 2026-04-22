use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LegacyTaskResultPayload {
    #[serde(rename = "Type")]
    pub(crate) type_id: i32,
    #[serde(rename = "Data")]
    pub(crate) data: String,
}

impl LegacyTaskResultPayload {
    pub(crate) const TYPE_ID: i32 = 9999;

    pub(crate) fn new(data: impl Into<String>) -> Self {
        Self {
            type_id: Self::TYPE_ID,
            data: data.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TaskErrorPayload {
    #[serde(rename = "Task")]
    pub(crate) task: String,
    #[serde(rename = "Error")]
    pub(crate) error: String,
}

impl TaskErrorPayload {
    pub(crate) fn new(task: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            task: task.into(),
            error: error.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// PID-monitor result
// ---------------------------------------------------------------------------

/// Go-parity tree-node entry in the process parent chain.
#[derive(Debug, Serialize)]
pub(crate) struct PidMonitorTreeNode {
    pub(crate) key: String,
    pub(crate) value: u32,
}

/// Zero-filled IO accounting stats (we forward zeros for Go parity).
#[derive(Debug, Default, Serialize)]
pub(crate) struct PidMonitorIOStats {
    #[serde(rename = "RChar")]
    pub(crate) rchar: u64,
    #[serde(rename = "WChar")]
    pub(crate) wchar: u64,
    #[serde(rename = "SyscallRead")]
    pub(crate) syscall_read: u64,
    #[serde(rename = "SyscallWrite")]
    pub(crate) syscall_write: u64,
    #[serde(rename = "ReadBytes")]
    pub(crate) read_bytes: u64,
    #[serde(rename = "WriteBytes")]
    pub(crate) write_bytes: u64,
}

/// Zero-filled memory stats.
#[derive(Debug, Default, Serialize)]
pub(crate) struct PidMonitorStatm {
    #[serde(rename = "Size")]
    pub(crate) size: u64,
    #[serde(rename = "Resident")]
    pub(crate) resident: u64,
    #[serde(rename = "Shared")]
    pub(crate) shared: u64,
    #[serde(rename = "Text")]
    pub(crate) text: u64,
    #[serde(rename = "Lib")]
    pub(crate) lib: u64,
    #[serde(rename = "Data")]
    pub(crate) data: u64,
    #[serde(rename = "Dt")]
    pub(crate) dt: u64,
}

/// Zero-filled net stats.
#[derive(Debug, Default, Serialize)]
pub(crate) struct PidMonitorNetStats {
    #[serde(rename = "ReadBytes")]
    pub(crate) read_bytes: u64,
    #[serde(rename = "WriteBytes")]
    pub(crate) write_bytes: u64,
}

/// Full pid-monitor task result payload (Go-parity field names).
#[derive(Debug, Serialize)]
pub(crate) struct PidMonitorResult {
    #[serde(rename = "Pid")]
    pub(crate) pid: u32,
    #[serde(rename = "ID")]
    pub(crate) id: u32,
    #[serde(rename = "Ppid")]
    pub(crate) ppid: u32,
    #[serde(rename = "PPID")]
    pub(crate) ppid_alias: u32,
    #[serde(rename = "Uid")]
    pub(crate) uid: u32,
    #[serde(rename = "UID")]
    pub(crate) uid_alias: u32,
    #[serde(rename = "Comm")]
    pub(crate) comm: String,
    #[serde(rename = "Path")]
    pub(crate) path: String,
    #[serde(rename = "Root")]
    pub(crate) root: String,
    #[serde(rename = "RealPath")]
    pub(crate) real_path: String,
    #[serde(rename = "Args")]
    pub(crate) args: Vec<String>,
    #[serde(rename = "Env")]
    pub(crate) env: HashMap<String, String>,
    #[serde(rename = "CWD")]
    pub(crate) cwd: String,
    #[serde(rename = "Checksums")]
    pub(crate) checksums: HashMap<String, String>,
    #[serde(rename = "IOStats")]
    pub(crate) io_stats: PidMonitorIOStats,
    #[serde(rename = "Statm")]
    pub(crate) statm: PidMonitorStatm,
    #[serde(rename = "Status")]
    pub(crate) status: String,
    #[serde(rename = "Stat")]
    pub(crate) stat: String,
    #[serde(rename = "Maps")]
    pub(crate) maps: String,
    #[serde(rename = "Stack")]
    pub(crate) stack: String,
    /// Always null — `()` serialises as JSON null.
    #[serde(rename = "Descriptors")]
    pub(crate) descriptors: (),
    #[serde(rename = "NetStats")]
    pub(crate) net_stats: PidMonitorNetStats,
    #[serde(rename = "Tree")]
    pub(crate) tree: Vec<PidMonitorTreeNode>,
}

// ---------------------------------------------------------------------------
// Node-monitor result
// ---------------------------------------------------------------------------

/// Full node-monitor task result payload (wraps `rustix::system::Sysinfo`).
#[derive(Debug, Serialize)]
pub(crate) struct NodeMonitorResult {
    #[serde(rename = "Uptime")]
    pub(crate) uptime: i64,
    #[serde(rename = "Loads")]
    pub(crate) loads: [u64; 3],
    #[serde(rename = "Totalram")]
    pub(crate) totalram: u64,
    #[serde(rename = "Freeram")]
    pub(crate) freeram: u64,
    #[serde(rename = "Sharedram")]
    pub(crate) sharedram: u64,
    #[serde(rename = "Bufferram")]
    pub(crate) bufferram: u64,
    #[serde(rename = "Totalswap")]
    pub(crate) totalswap: u64,
    #[serde(rename = "Freeswap")]
    pub(crate) freeswap: u64,
    #[serde(rename = "Procs")]
    pub(crate) procs: u16,
    #[serde(rename = "Totalhigh")]
    pub(crate) totalhigh: u64,
    #[serde(rename = "Freehigh")]
    pub(crate) freehigh: u64,
    #[serde(rename = "Unit")]
    pub(crate) unit: u32,
}

// ---------------------------------------------------------------------------
// Downloader result
// ---------------------------------------------------------------------------

/// Full downloader task result payload.
#[derive(Debug, Serialize)]
pub(crate) struct DownloaderResult {
    #[serde(rename = "Task")]
    pub(crate) task: &'static str,
    #[serde(rename = "Status")]
    pub(crate) status: &'static str,
    #[serde(rename = "Sources")]
    pub(crate) sources: u32,
    #[serde(rename = "Updated")]
    pub(crate) updated: u32,
    #[serde(rename = "Failed")]
    pub(crate) failed: u32,
    #[serde(rename = "Errors")]
    pub(crate) errors: Vec<String>,
}

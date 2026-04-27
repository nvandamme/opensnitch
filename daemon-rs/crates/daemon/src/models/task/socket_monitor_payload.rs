/// Wire-contract types for socket-monitor task results sent to the UI.
///
/// These are **Go-parity** shapes — field names match the Go daemon's JSON
/// output so the existing UI can consume them without changes.
/// Serialised to JSON at the transport boundary; the structs themselves are
/// codec-agnostic.
use std::collections::HashMap;

use serde::Serialize;

/// A single row in the socket-monitor table.
#[derive(Debug, Serialize)]
pub(crate) struct SocketMonitorRow {
    #[serde(rename = "Socket")]
    pub(crate) socket: SocketEntry,
    #[serde(rename = "Iface")]
    pub(crate) iface: String,
    #[serde(rename = "PID")]
    pub(crate) pid: i32,
    #[serde(rename = "Mark")]
    pub(crate) mark: u32,
    #[serde(rename = "Proto")]
    pub(crate) proto: u32,
}

/// The socket identity and status fields.
#[derive(Debug, Serialize)]
pub(crate) struct SocketEntry {
    #[serde(rename = "ID")]
    pub(crate) id: SocketId,
    #[serde(rename = "Expires")]
    pub(crate) expires: u32,
    #[serde(rename = "RQueue")]
    pub(crate) rqueue: u32,
    #[serde(rename = "WQueue")]
    pub(crate) wqueue: u32,
    #[serde(rename = "UID")]
    pub(crate) uid: u32,
    #[serde(rename = "INode")]
    pub(crate) inode: u32,
    #[serde(rename = "Family")]
    pub(crate) family: u8,
    #[serde(rename = "State")]
    pub(crate) state: u8,
    #[serde(rename = "Timer")]
    pub(crate) timer: u8,
    #[serde(rename = "Retrans")]
    pub(crate) retrans: u8,
}

/// Socket 5-tuple + cookie identification.
#[derive(Debug, Serialize)]
pub(crate) struct SocketId {
    #[serde(rename = "Source")]
    pub(crate) source: String,
    #[serde(rename = "Destination")]
    pub(crate) destination: String,
    #[serde(rename = "Cookie")]
    pub(crate) cookie: [u32; 2],
    #[serde(rename = "Interface")]
    pub(crate) interface: u32,
    #[serde(rename = "SourcePort")]
    pub(crate) source_port: u16,
    #[serde(rename = "DestinationPort")]
    pub(crate) destination_port: u16,
}

/// Process information entry in the socket-monitor processes map.
#[derive(Debug, Serialize)]
pub(crate) struct SocketMonitorProcessEntry {
    #[serde(rename = "Pid")]
    pub(crate) pid: i32,
    #[serde(rename = "Path")]
    pub(crate) path: String,
    #[serde(rename = "Comm")]
    pub(crate) comm: String,
    #[serde(rename = "Args")]
    pub(crate) args: Vec<String>,
    #[serde(rename = "CWD")]
    pub(crate) cwd: String,
}

/// Full socket-monitor task result payload.
#[derive(Debug, Serialize)]
pub(crate) struct SocketMonitorPayload {
    #[serde(rename = "Table")]
    pub(crate) table: Vec<SocketMonitorRow>,
    /// Keyed by string PID (matching Go's `map[string]interface{}`).
    #[serde(rename = "Processes")]
    pub(crate) processes: HashMap<String, SocketMonitorProcessEntry>,
}

impl SocketMonitorPayload {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            table: Vec::with_capacity(capacity),
            processes: HashMap::new(),
        }
    }
}

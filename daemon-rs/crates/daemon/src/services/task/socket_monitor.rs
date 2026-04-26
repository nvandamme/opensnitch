// Socket-monitor row building helpers — extracted from runtime_handlers.rs
// to respect the ~500-line file-size enforcement rule (DESIGN_RULES §2).
//
// All functions are stateless pure helpers scoped to `services::task`.
// Callers in runtime_handlers.rs reach these as `socket_monitor::fn_name(...)`.

use std::collections::HashMap;

use crate::{
    models::{
        proc_net_packet::{ProcNetPacketRow, ProcNetXdpRow},
        socket_monitor_payload::{
            SocketEntry, SocketId, SocketMonitorProcessEntry, SocketMonitorRow,
        },
        socket_state::SocketInfo,
    },
    services::{connection::ConnectionService, process::ProcessService},
};

// ── Process cache helpers ─────────────────────────────────────────────────

pub(super) async fn ensure_process_entry(
    process: &ProcessService,
    process_map: &mut HashMap<String, SocketMonitorProcessEntry>,
    pid: Option<u32>,
) {
    let key = pid
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-1".to_string());

    if process_map.contains_key(&key) {
        return;
    }

    if let Some(pid) = pid {
        if let Ok(info) = process.inspect(pid).await {
            let process_path = info.path.clone();
            let comm = std::path::Path::new(&process_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            process_map.insert(
                key,
                SocketMonitorProcessEntry {
                    pid: pid as i32,
                    path: process_path,
                    comm,
                    args: info.args,
                    cwd: info.cwd.unwrap_or_default(),
                },
            );
            return;
        }

        process_map.insert(
            key,
            SocketMonitorProcessEntry {
                pid: pid as i32,
                path: String::new(),
                comm: String::new(),
                args: Vec::new(),
                cwd: String::new(),
            },
        );
        return;
    }

    process_map.insert(
        key,
        SocketMonitorProcessEntry {
            pid: -1,
            path: String::new(),
            comm: String::new(),
            args: Vec::new(),
            cwd: String::new(),
        },
    );
}

pub(super) async fn resolve_cached_socket_pid(
    inode_pid_cache: &mut HashMap<u32, Option<u32>>,
    inode: u32,
) -> Option<u32> {
    if inode == 0 {
        return None;
    }

    if let Some(cached) = inode_pid_cache.get(&inode) {
        return *cached;
    }

    let resolved = ConnectionService::resolve_pid_by_inode_async(inode).await;
    inode_pid_cache.insert(inode, resolved);
    resolved
}

// ── Interface name cache ──────────────────────────────────────────────────

pub(super) async fn resolve_cached_iface_name(
    iface_cache: &mut HashMap<u32, String>,
    rtnl_iface_map: Option<&HashMap<u32, String>>,
    iface: u32,
) -> String {
    if iface == 0 {
        return String::new();
    }

    if let Some(name) = iface_cache.get(&iface) {
        return name.clone();
    }

    let name = if let Some(name) = rtnl_iface_map.and_then(|m| m.get(&iface).cloned()) {
        name
    } else {
        match crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_by_index_async(
            iface,
        )
        .await
        {
            Ok(Some(name)) => name,
            Ok(None) => String::new(),
            Err(err) => {
                tracing::warn!(iface, detail = %err, "failed to resolve interface name via rtnetlink");
                String::new()
            }
        }
    };
    iface_cache.insert(iface, name.clone());
    name
}

pub(super) async fn fetch_iface_name_map_rtnetlink() -> Option<HashMap<u32, String>> {
    match crate::platform::netlink::ifaces::NetIfaceAdapter::interface_name_map_async().await {
        Ok(map) if map.is_empty() => None,
        Ok(map) => Some(map),
        Err(err) => {
            tracing::warn!(detail = %err, "failed to enumerate interfaces via rtnetlink");
            None
        }
    }
}

// ── Composite row preparation ─────────────────────────────────────────────

pub(super) async fn prepare_socket_monitor_row(
    process: &ProcessService,
    process_map: &mut HashMap<String, SocketMonitorProcessEntry>,
    inode_pid_cache: &mut HashMap<u32, Option<u32>>,
    iface_cache: &mut HashMap<u32, String>,
    rtnl_iface_map: Option<&HashMap<u32, String>>,
    inode: u32,
    iface: u32,
) -> (Option<u32>, String) {
    let pid = resolve_cached_socket_pid(inode_pid_cache, inode).await;
    ensure_process_entry(process, process_map, pid).await;
    let iface_name = resolve_cached_iface_name(iface_cache, rtnl_iface_map, iface).await;
    (pid, iface_name)
}

// ── Row builders ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(super) fn socket_monitor_row(
    source: &str,
    destination: &str,
    cookie: [u32; 2],
    iface: u32,
    source_port: u16,
    destination_port: u16,
    expires: u32,
    rqueue: u32,
    wqueue: u32,
    uid: u32,
    inode: u32,
    family: u8,
    state: u8,
    timer: u8,
    retrans: u8,
    iface_name: String,
    pid: Option<u32>,
    mark: u32,
    proto: u32,
) -> SocketMonitorRow {
    SocketMonitorRow {
        socket: SocketEntry {
            id: SocketId {
                source: source.to_string(),
                destination: destination.to_string(),
                cookie,
                interface: iface,
                source_port,
                destination_port,
            },
            expires,
            rqueue,
            wqueue,
            uid,
            inode,
            family,
            state,
            timer,
            retrans,
        },
        iface: iface_name,
        pid: pid.map(|v| v as i32).unwrap_or(-1),
        mark,
        proto,
    }
}

pub(super) fn socket_monitor_diag_row(
    socket: &SocketInfo,
    iface_name: String,
    pid: Option<u32>,
    proto: u32,
) -> SocketMonitorRow {
    socket_monitor_row(
        socket.src.to_string().as_str(),
        socket.dst.to_string().as_str(),
        [socket.cookie0, socket.cookie1],
        socket.iface,
        socket.src_port,
        socket.dst_port,
        socket.expires,
        socket.rqueue,
        socket.wqueue,
        socket.uid,
        socket.inode,
        socket.family,
        socket.state,
        socket.timer,
        socket.retrans,
        iface_name,
        pid,
        socket.mark,
        proto,
    )
}

pub(super) fn socket_monitor_packet_row(
    packet: &ProcNetPacketRow,
    iface_name: String,
    pid: Option<u32>,
) -> SocketMonitorRow {
    // Keep Go parity: /proc fallback packet sockets are tagged as raw.
    socket_monitor_row(
        "",
        "",
        [0, 0],
        packet.iface,
        0,
        0,
        0,
        0,
        0,
        packet.uid,
        packet.inode,
        nix::libc::AF_PACKET as u8,
        0,
        0,
        0,
        iface_name,
        pid,
        0,
        nix::libc::IPPROTO_RAW as u32,
    )
}

pub(super) fn socket_monitor_xdp_row(
    xdp: &ProcNetXdpRow,
    iface_name: String,
    pid: Option<u32>,
) -> SocketMonitorRow {
    socket_monitor_row(
        "",
        "",
        [xdp.cookie0, xdp.cookie1],
        xdp.iface,
        0,
        0,
        0,
        0,
        0,
        xdp.uid,
        xdp.inode,
        nix::libc::AF_XDP as u8,
        0,
        0,
        0,
        iface_name,
        pid,
        0,
        nix::libc::IPPROTO_RAW as u32,
    )
}

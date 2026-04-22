use crate::models::{
    connection_owner::{ConnectionOwner, ConnectionOwnerCacheKey},
    connection_state::{ConnectionAttempt, TransportProtocol},
};
use crate::platform::ports::socket_diag_port::{NativeSocketDiagPort, SocketDiagPlatformPort};
use crate::utils::proc_fs::proc_pid_exists;
use crate::utils::proc_net::read_proc_net_packet_rows;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::ConnectionService;

impl ConnectionService {
    pub(crate) fn resolve_pid_by_inode(inode: u32) -> Option<u32> {
        Self::resolve_pid_by_inode_with_key(inode, None)
    }

    pub(crate) async fn resolve_pid_by_inode_async(inode: u32) -> Option<u32> {
        tokio::task::spawn_blocking(move || Self::resolve_pid_by_inode(inode))
            .await
            .ok()
            .flatten()
    }

    fn pid_owns_inode(pid: u32, inode: u32) -> bool {
        let mut fd_dir = PathBuf::with_capacity(24);
        fd_dir.push("/proc");
        fd_dir.push(pid.to_string());
        fd_dir.push("fd");
        Self::pid_owns_inode_at(inode, &fd_dir)
    }

    fn pid_owns_inode_at(inode: u32, fd_dir: &Path) -> bool {
        let Ok(fds) = std::fs::read_dir(fd_dir) else {
            return false;
        };

        for fd_entry in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(found_inode) = Self::parse_socket_inode(&target)
                && found_inode == inode
            {
                return true;
            }
        }

        false
    }

    pub(super) fn resolve_pid_by_inode_with_key(
        inode: u32,
        inode_key: Option<&ConnectionOwnerCacheKey>,
    ) -> Option<u32> {
        if inode == 0 {
            return None;
        }

        if let Some(key) = inode_key {
            if let Some(pid) = Self::key_cache().get(key)
                && proc_pid_exists(pid)
                && Self::pid_owns_inode(pid, inode)
            {
                return Some(pid);
            }
        }

        if let Some(pid) = Self::cache().get(&inode)
            && proc_pid_exists(pid)
            && Self::pid_owns_inode(pid, inode)
        {
            return Some(pid);
        }

        let proc_entries = std::fs::read_dir("/proc").ok()?;
        // Pre-allocate once and reuse across all pid candidates to avoid one
        // format!("/proc/{pid}/fd") heap allocation per iteration.
        let mut fd_dir = PathBuf::with_capacity(24);
        for entry in proc_entries.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
                continue;
            };

            fd_dir.clear();
            fd_dir.push("/proc");
            fd_dir.push(&name);
            fd_dir.push("fd");

            if Self::pid_owns_inode_at(inode, &fd_dir) {
                Self::cache().insert(inode, pid);
                if let Some(key) = inode_key {
                    Self::key_cache().insert(*key, pid);
                }
                return Some(pid);
            }
        }

        None
    }

    fn resolve_owner_from_packet_sockets(
        protocol: TransportProtocol,
        uid_hint: Option<u32>,
    ) -> Option<ConnectionOwner> {
        if !matches!(protocol, TransportProtocol::Icmp) {
            return None;
        }
        let hint = uid_hint.filter(|v| *v != 0)?;
        let entries = read_proc_net_packet_rows();
        // Single-slot tracking: return Some only when exactly one owner matches.
        // On a second *different* entry we return None immediately — no Vec needed.
        let mut found: Option<ConnectionOwner> = None;
        for entry in entries {
            if entry.inode == 0 || entry.uid != hint {
                continue;
            }
            let Some(pid) = Self::resolve_pid_by_inode(entry.inode) else {
                continue;
            };
            match &found {
                None => found = Some(ConnectionOwner { uid: entry.uid, pid }),
                Some(_) => return None, // ambiguous: more than one socket owner
            }
        }
        found
    }

    fn resolve_owner_by_connection_fallback(
        protocol: TransportProtocol,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        uid_hint: Option<u32>,
    ) -> Option<ConnectionOwner> {
        for path in Self::proc_net_paths(protocol) {
            let Ok(file) = std::fs::File::open(path) else {
                continue;
            };
            // BufReader: iterate line-by-line without loading the entire
            // /proc/net/{tcp,tcp6,…} file into a heap String; return early on match.
            let mut lines = BufReader::new(file).lines();
            lines.next(); // skip header
            for line in lines.filter_map(|r| r.ok()) {
                let Some(((local_ip, local_port), (remote_ip, remote_port), uid, inode)) =
                    Self::parse_proc_net_row(&line)
                else {
                    continue;
                };
                if inode == 0 {
                    continue;
                }
                let exact_match = local_ip == src
                    && local_port == src_port
                    && remote_ip == dst
                    && remote_port == dst_port;
                let reverse_match = local_ip == dst
                    && local_port == dst_port
                    && remote_ip == src
                    && remote_port == src_port;
                if !exact_match && !reverse_match {
                    continue;
                }
                let lookup_key = if exact_match {
                    Self::inode_lookup_key(protocol, src, src_port, dst, dst_port)
                } else {
                    Self::inode_lookup_key(protocol, dst, dst_port, src, src_port)
                };
                let Some(pid) = Self::resolve_pid_by_inode_with_key(inode, Some(&lookup_key))
                else {
                    continue;
                };
                return Some(ConnectionOwner { uid, pid });
            }
        }
        Self::resolve_owner_from_packet_sockets(protocol, uid_hint)
    }

    pub(super) fn enrich_connection_owner(attempt: &mut ConnectionAttempt) {
        let src = attempt.src_addr;
        let dst = attempt.dst_addr;

        let family = Self::infer_family(attempt);
        let Some(ipproto) = Self::protocol_to_ipproto(attempt.protocol) else {
            return;
        };

        if let Ok(candidates) = NativeSocketDiagPort::find_socket_candidates(
            family,
            ipproto,
            src,
            attempt.src_port,
            dst,
            attempt.dst_port,
        ) {
            let lookup_key = Self::inode_lookup_key(
                attempt.protocol,
                src,
                attempt.src_port,
                dst,
                attempt.dst_port,
            );
            for sock in candidates {
                attempt.uid = sock.uid;
                if let Some(pid) =
                    Self::resolve_pid_by_inode_with_key(sock.inode, Some(&lookup_key))
                {
                    attempt.pid = pid;
                    return;
                }
            }
        }

        if let Ok(candidates) = NativeSocketDiagPort::find_socket_candidates(
            family,
            ipproto,
            dst,
            attempt.dst_port,
            src,
            attempt.src_port,
        ) {
            let reverse_lookup_key = Self::inode_lookup_key(
                attempt.protocol,
                dst,
                attempt.dst_port,
                src,
                attempt.src_port,
            );
            for sock in candidates {
                attempt.uid = sock.uid;
                if let Some(pid) =
                    Self::resolve_pid_by_inode_with_key(sock.inode, Some(&reverse_lookup_key))
                {
                    attempt.pid = pid;
                    return;
                }
            }
        }

        if let Some(owner) = Self::resolve_owner_by_connection_fallback(
            attempt.protocol,
            src,
            attempt.src_port,
            dst,
            attempt.dst_port,
            Some(attempt.uid),
        ) {
            if attempt.uid == 0 {
                attempt.uid = owner.uid;
            }
            if attempt.pid == 0 {
                attempt.pid = owner.pid;
            }
        }
    }
}

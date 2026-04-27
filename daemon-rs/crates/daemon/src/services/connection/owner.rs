use crate::models::{
    connection::owner::{ConnectionOwner, ConnectionOwnerCacheKey},
    connection::state::{ConnectionAttempt, TransportProtocol},
};
use crate::platform::netstat::socket_diag::SocketDiagAdapter;
use crate::platform::procmon::procfs;
use crate::utils::proc_fs::proc_pid_exists;
use crate::utils::proc_net::read_proc_net_packet_rows;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;

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
                && procfs::pid_owns_inode(pid, inode)
            {
                return Some(pid);
            }
        }

        if let Some(pid) = Self::cache().get(&inode)
            && proc_pid_exists(pid)
            && procfs::pid_owns_inode(pid, inode)
        {
            return Some(pid);
        }

        for pid in procfs::list_pids() {
            if procfs::pid_owns_inode(pid, inode) {
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
                None => {
                    found = Some(ConnectionOwner {
                        uid: entry.uid,
                        pid,
                    })
                }
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

    /// Resolve connection owner via a single socket-diag pass that checks
    /// both forward and reverse socket matching in one iteration.  This
    /// avoids a second syscall when the forward pass finds nothing.
    pub(super) fn enrich_connection_owner(attempt: &mut ConnectionAttempt) {
        let src = attempt.src_addr;
        let dst = attempt.dst_addr;

        let family = Self::infer_family(attempt);
        let Some(ipproto) = Self::protocol_to_ipproto(attempt.protocol) else {
            return;
        };

        let lookup_key = Self::inode_lookup_key(
            attempt.protocol,
            src,
            attempt.src_port,
            dst,
            attempt.dst_port,
        );
        let reverse_lookup_key = Self::inode_lookup_key(
            attempt.protocol,
            dst,
            attempt.dst_port,
            src,
            attempt.src_port,
        );

        if let Ok(candidates) = SocketDiagAdapter::find_socket_candidates(
            family,
            ipproto,
            src,
            attempt.src_port,
            dst,
            attempt.dst_port,
        ) {
            for sock in candidates {
                // Try forward match first (sock.src == src), then reverse (sock.src == dst).
                let resolved = if sock.src == src
                    && sock.src_port == attempt.src_port
                    && sock.dst == dst
                    && sock.dst_port == attempt.dst_port
                {
                    Some((sock.uid, sock.inode, &lookup_key))
                } else if sock.src == dst
                    && sock.src_port == attempt.dst_port
                    && sock.dst == src
                    && sock.dst_port == attempt.src_port
                {
                    Some((sock.uid, sock.inode, &reverse_lookup_key))
                } else {
                    None
                };
                if let Some((uid, inode, key)) = resolved {
                    attempt.uid = uid;
                    if let Some(pid) = Self::resolve_pid_by_inode_with_key(inode, Some(key)) {
                        attempt.pid = pid;
                        return;
                    }
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

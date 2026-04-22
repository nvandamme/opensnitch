use std::{
    collections::HashMap,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    process::Command,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use nix::libc;

use crate::adapters::socket_diag::SocketDiagAdapter;
use crate::models::{
    connection_owner::ConnectionOwner,
    connection_state::{ConnectionAttempt, TransportProtocol},
    proc_net_packet::ProcNetPacketRow,
};
use crate::utils::lru_cache::LruCache;

#[cfg(not(test))]
const DEFAULT_INODE_TO_PID_CACHE_CAPACITY: usize = 262_144;
#[cfg(test)]
const DEFAULT_INODE_TO_PID_CACHE_CAPACITY: usize = 8_192;

#[cfg(not(test))]
const DEFAULT_INODE_KEY_TO_PID_CACHE_CAPACITY: usize = 262_144;
#[cfg(test)]
const DEFAULT_INODE_KEY_TO_PID_CACHE_CAPACITY: usize = 8_192;

static INODE_TO_PID_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_INODE_TO_PID_CACHE_CAPACITY);
static INODE_KEY_TO_PID_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_INODE_KEY_TO_PID_CACHE_CAPACITY);

static INODE_TO_PID: OnceLock<Mutex<LruCache<u32, u32>>> = OnceLock::new();
static INODE_KEY_TO_PID: OnceLock<Mutex<LruCache<String, u32>>> = OnceLock::new();
static BPF_MAP_IDS: OnceLock<Mutex<BpfMapIdCache>> = OnceLock::new();

pub(crate) struct PidResolverState;

#[derive(Default)]
struct BpfMapIdCache {
    refreshed_at: Option<Instant>,
    by_name: HashMap<String, u32>,
}

impl BpfMapIdCache {
    fn global() -> &'static Mutex<Self> {
        BPF_MAP_IDS.get_or_init(|| Mutex::new(Self::default()))
    }

    fn get_map_id(&mut self, map_name: &str) -> Option<u32> {
        let now = Instant::now();
        let stale = self
            .refreshed_at
            .map(|ts| now.duration_since(ts) > Duration::from_secs(30))
            .unwrap_or(true);

        if stale {
            self.by_name = Self::list_bpf_maps();
            self.refreshed_at = Some(now);
        }

        self.by_name.get(map_name).copied()
    }

    fn list_bpf_maps() -> HashMap<String, u32> {
        let out = Command::new("bpftool").args(["-j", "map", "show"]).output();
        let Ok(out) = out else {
            return HashMap::new();
        };
        if !out.status.success() {
            return HashMap::new();
        }

        let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        let Some(items) = parsed.as_array() else {
            return HashMap::new();
        };

        let mut by_name = HashMap::new();
        for item in items {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(id) = item
                .get("id")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
            else {
                continue;
            };
            by_name.insert(name.to_string(), id);
        }

        by_name
    }
}

impl PidResolverState {
    pub(crate) fn configure_cache_capacities(inode_cap: usize, inode_key_cap: usize) {
        let inode_cap = inode_cap.max(1);
        let inode_key_cap = inode_key_cap.max(1);
        INODE_TO_PID_CACHE_CAPACITY.store(inode_cap, Ordering::Relaxed);
        INODE_KEY_TO_PID_CACHE_CAPACITY.store(inode_key_cap, Ordering::Relaxed);

        if let Some(cache) = INODE_TO_PID.get()
            && let Ok(mut cache) = cache.lock()
        {
            cache.set_capacity(inode_cap);
        }
        if let Some(cache) = INODE_KEY_TO_PID.get()
            && let Ok(mut cache) = cache.lock()
        {
            cache.set_capacity(inode_key_cap);
        }
    }

    fn parse_proc_net_row(line: &str) -> Option<((String, u16), (String, u16), u32, u32)> {
        let mut cols = line.split_whitespace();
        let mut local = None;
        let mut remote = None;
        let mut uid = None;
        let mut inode = None;

        for (idx, col) in (&mut cols).enumerate() {
            match idx {
                1 => local = Self::parse_proc_addr_port(col),
                2 => remote = Self::parse_proc_addr_port(col),
                7 => uid = col.parse::<u32>().ok(),
                9 => {
                    inode = col.parse::<u32>().ok();
                    break;
                }
                _ => {}
            }
        }

        Some((local?, remote?, uid.unwrap_or(0), inode.unwrap_or(0)))
    }

    fn cache() -> &'static Mutex<LruCache<u32, u32>> {
        INODE_TO_PID.get_or_init(|| {
            Mutex::new(LruCache::new(
                INODE_TO_PID_CACHE_CAPACITY.load(Ordering::Relaxed).max(1),
            ))
        })
    }

    fn key_cache() -> &'static Mutex<LruCache<String, u32>> {
        INODE_KEY_TO_PID.get_or_init(|| {
            Mutex::new(LruCache::new(
                INODE_KEY_TO_PID_CACHE_CAPACITY
                    .load(Ordering::Relaxed)
                    .max(1),
            ))
        })
    }

    fn proc_net_paths(protocol: TransportProtocol) -> &'static [&'static str] {
        match protocol {
            TransportProtocol::Tcp => &["/proc/net/tcp", "/proc/net/tcp6"],
            TransportProtocol::Udp => &["/proc/net/udp", "/proc/net/udp6"],
            TransportProtocol::UdpLite => &["/proc/net/udplite", "/proc/net/udplite6"],
            TransportProtocol::Sctp => &["/proc/net/sctp/eps", "/proc/net/sctp/assocs"],
            TransportProtocol::Icmp => &["/proc/net/icmp", "/proc/net/icmp6"],
        }
    }

    fn bpf_map_name(
        protocol: TransportProtocol,
        src_ip: &str,
        dst_ip: &str,
    ) -> Option<&'static str> {
        match protocol {
            TransportProtocol::Tcp => {
                if src_ip.contains(':') || dst_ip.contains(':') {
                    Some("tcpv6Map")
                } else {
                    Some("tcpMap")
                }
            }
            TransportProtocol::Udp | TransportProtocol::UdpLite => {
                if src_ip.contains(':') || dst_ip.contains(':') {
                    Some("udpv6Map")
                } else {
                    Some("udpMap")
                }
            }
            TransportProtocol::Sctp | TransportProtocol::Icmp => None,
        }
    }

    fn parse_proc_addr_port(value: &str) -> Option<(String, u16)> {
        let mut parts = value.split(':');
        let addr_hex = parts.next()?;
        let port_hex = parts.next()?;

        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let ip = Self::parse_proc_ip(addr_hex)?;
        Some((ip, port))
    }

    fn parse_proc_ip(value: &str) -> Option<String> {
        if value.len() == 8 {
            let raw = u32::from_str_radix(value, 16).ok()?;
            let b = raw.to_le_bytes();
            return Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string());
        }

        if value.len() == 32 {
            let mut words = [0_u32; 4];
            for (i, chunk) in value.as_bytes().chunks(8).enumerate() {
                if i >= 4 {
                    return None;
                }
                let chunk = std::str::from_utf8(chunk).ok()?;
                words[i] = u32::from_str_radix(chunk, 16).ok()?;
            }

            let mut octets = [0_u8; 16];
            for (i, word) in words.iter().enumerate() {
                let b = word.to_le_bytes();
                let start = i * 4;
                octets[start..start + 4].copy_from_slice(&b);
            }

            return Some(Ipv6Addr::from(octets).to_string());
        }

        None
    }

    fn parse_socket_inode(value: &str) -> Option<u32> {
        if !value.starts_with("socket:[") || !value.ends_with(']') {
            return None;
        }
        value
            .trim_start_matches("socket:[")
            .trim_end_matches(']')
            .parse::<u32>()
            .ok()
    }

    fn parse_value_hex_bytes(value: &str) -> Option<Vec<u8>> {
        let mut collect = false;
        let mut out = Vec::new();
        for line in value.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("value:") {
                collect = true;
                continue;
            }
            if !collect {
                continue;
            }

            for tok in trimmed.split_whitespace() {
                let tok = tok.trim_end_matches(',').trim_end_matches(':');
                if tok.len() == 2
                    && tok.chars().all(|c| c.is_ascii_hexdigit())
                    && let Ok(v) = u8::from_str_radix(tok, 16)
                {
                    out.push(v);
                }
            }
        }

        if out.is_empty() { None } else { Some(out) }
    }

    fn protocol_name(protocol: TransportProtocol) -> &'static str {
        match protocol {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
            TransportProtocol::UdpLite => "udplite",
            TransportProtocol::Sctp => "sctp",
            TransportProtocol::Icmp => "icmp",
        }
    }

    fn inode_lookup_key(
        protocol: TransportProtocol,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            Self::protocol_name(protocol),
            src_ip,
            src_port,
            dst_ip,
            dst_port
        )
    }

    fn pid_owns_inode(pid: u32, inode: u32) -> bool {
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            return false;
        };

        for fd_entry in fds.flatten() {
            let Ok(target) = fs::read_link(fd_entry.path()) else {
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

    fn resolve_pid_by_inode_with_key(inode: u32, inode_key: Option<&str>) -> Option<u32> {
        if inode == 0 {
            return None;
        }

        if let Some(key) = inode_key {
            if let Some(pid) = Self::key_cache()
                .lock()
                .ok()
                .and_then(|mut m| m.get_cloned_by(key))
            {
                if Path::new(&format!("/proc/{pid}")).exists() && Self::pid_owns_inode(pid, inode) {
                    return Some(pid);
                }
            }
        }

        if let Some(pid) = Self::cache()
            .lock()
            .ok()
            .and_then(|mut m| m.get_cloned_by(&inode))
        {
            if Path::new(&format!("/proc/{pid}")).exists() && Self::pid_owns_inode(pid, inode) {
                return Some(pid);
            }
        }

        let proc_entries = fs::read_dir("/proc").ok()?;
        for entry in proc_entries.flatten() {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };

            if Self::pid_owns_inode(pid, inode) {
                if let Ok(mut m) = Self::cache().lock() {
                    m.insert(inode, pid);
                }
                if let Some(key) = inode_key
                    && let Ok(mut m) = Self::key_cache().lock()
                {
                    m.insert(key.to_string(), pid);
                }
                return Some(pid);
            }
        }

        None
    }

    fn infer_family(attempt: &ConnectionAttempt) -> u8 {
        match attempt.src_addr {
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
        }
    }

    fn protocol_to_ipproto(protocol: TransportProtocol) -> Option<u8> {
        match protocol {
            TransportProtocol::Tcp => Some(libc::IPPROTO_TCP as u8),
            TransportProtocol::Udp => Some(libc::IPPROTO_UDP as u8),
            TransportProtocol::UdpLite => Some(136_u8),
            TransportProtocol::Sctp => Some(132_u8),
            // Keep Go netlink parity: ICMP ownership queries use RAW socket diag lookup.
            TransportProtocol::Icmp => Some(libc::IPPROTO_RAW as u8),
        }
    }

    fn parse_proc_net_packet() -> std::io::Result<Vec<ProcNetPacketRow>> {
        let contents = fs::read_to_string("/proc/net/packet")?;
        let mut out = Vec::new();

        for line in contents.lines().skip(1) {
            let mut iface = None;
            let mut uid = None;
            let mut inode = None;

            for (idx, col) in line.split_whitespace().enumerate() {
                match idx {
                    4 => iface = col.parse::<u32>().ok(),
                    7 => uid = col.parse::<u32>().ok(),
                    8 => {
                        inode = col.parse::<u32>().ok();
                        break;
                    }
                    _ => {}
                }
            }

            let (Some(iface), Some(uid), Some(inode)) = (iface, uid, inode) else {
                continue;
            };
            out.push(ProcNetPacketRow { iface, uid, inode });
        }

        Ok(out)
    }

    fn build_bpf_key(
        protocol: TransportProtocol,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<Vec<u8>> {
        let is_ipv6 = src_ip.contains(':') || dst_ip.contains(':');
        match protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp | TransportProtocol::UdpLite => {
                if is_ipv6 {
                    let src = src_ip.parse::<Ipv6Addr>().ok()?.octets();
                    let dst = dst_ip.parse::<Ipv6Addr>().ok()?.octets();
                    let mut key = vec![0_u8; 36];
                    key[0..2].copy_from_slice(&src_port.to_ne_bytes());
                    key[2..18].copy_from_slice(&dst);
                    key[18..20].copy_from_slice(&dst_port.to_be_bytes());
                    key[20..36].copy_from_slice(&src);
                    Some(key)
                } else {
                    let src = src_ip.parse::<Ipv4Addr>().ok()?.octets();
                    let dst = dst_ip.parse::<Ipv4Addr>().ok()?.octets();
                    let mut key = vec![0_u8; 12];
                    key[0..2].copy_from_slice(&src_port.to_ne_bytes());
                    key[2..6].copy_from_slice(&dst);
                    key[6..8].copy_from_slice(&dst_port.to_be_bytes());
                    key[8..12].copy_from_slice(&src);
                    Some(key)
                }
            }
            TransportProtocol::Sctp | TransportProtocol::Icmp => None,
        }
    }

    fn lookup_bpf_owner(map_id: u32, key: &[u8]) -> Option<(u32, u32)> {
        let mut args = vec![
            "map".to_string(),
            "lookup".to_string(),
            "id".to_string(),
            map_id.to_string(),
            "key".to_string(),
            "hex".to_string(),
        ];
        for b in key {
            args.push(format!("{b:02x}"));
        }

        let out = Command::new("bpftool").args(&args).output().ok()?;
        if !out.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&out.stdout);
        let Some(value_bytes) = Self::parse_value_hex_bytes(&text) else {
            return None;
        };
        if value_bytes.len() < 16 {
            return None;
        }

        let pid = u64::from_ne_bytes(value_bytes[0..8].try_into().ok()?) as u32;
        let uid = u64::from_ne_bytes(value_bytes[8..16].try_into().ok()?) as u32;
        Some((pid, uid))
    }

    fn resolve_owner_from_packet_sockets(
        protocol: TransportProtocol,
        uid_hint: Option<u32>,
    ) -> Option<ConnectionOwner> {
        // Packet sockets do not carry 5-tuple information; only use as constrained fallback.
        if !matches!(protocol, TransportProtocol::Icmp) {
            return None;
        }

        let hint = uid_hint.filter(|v| *v != 0)?;
        let entries = Self::parse_proc_net_packet().ok()?;
        let mut candidates = Vec::new();

        for entry in entries {
            if entry.inode == 0 {
                continue;
            }

            if entry.uid != hint {
                continue;
            }

            if let Some(pid) = Self::resolve_pid_by_inode(entry.inode) {
                candidates.push(ConnectionOwner {
                    uid: entry.uid,
                    pid,
                });
            }
        }

        if candidates.len() == 1 {
            candidates.into_iter().next()
        } else {
            None
        }
    }
}

impl PidResolverState {
    #[cfg(test)]
    pub(crate) fn probe_parse_proc_addr_port(value: &str) -> Option<(String, u16)> {
        Self::parse_proc_addr_port(value)
    }

    #[cfg(test)]
    pub(crate) fn probe_parse_proc_ip(value: &str) -> Option<String> {
        Self::parse_proc_ip(value)
    }

    #[cfg(test)]
    pub(crate) fn probe_parse_socket_inode(value: &str) -> Option<u32> {
        Self::parse_socket_inode(value)
    }

    #[cfg(test)]
    pub(crate) fn probe_parse_value_hex_bytes(value: &str) -> Option<Vec<u8>> {
        Self::parse_value_hex_bytes(value)
    }

    #[cfg(test)]
    pub(crate) fn probe_protocol_to_ipproto(protocol: TransportProtocol) -> Option<u8> {
        Self::protocol_to_ipproto(protocol)
    }

    #[cfg(test)]
    pub(crate) fn probe_cache_capacities() -> (usize, usize) {
        (
            INODE_TO_PID_CACHE_CAPACITY.load(Ordering::Relaxed),
            INODE_KEY_TO_PID_CACHE_CAPACITY.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(crate) fn probe_reset_caches() {
        if let Ok(mut cache) = Self::cache().lock() {
            cache.clear();
        }
        if let Ok(mut cache) = Self::key_cache().lock() {
            cache.clear();
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_insert_inode_cache(inode: u32, pid: u32) {
        if let Ok(mut cache) = Self::cache().lock() {
            cache.insert(inode, pid);
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_insert_key_cache(key: &str, pid: u32) {
        if let Ok(mut cache) = Self::key_cache().lock() {
            cache.insert(key.to_string(), pid);
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_inode_cache_len() -> usize {
        Self::cache().lock().map(|cache| cache.len()).unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn probe_key_cache_len() -> usize {
        Self::key_cache()
            .lock()
            .map(|cache| cache.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn probe_get_inode_cache(inode: u32) -> Option<u32> {
        Self::cache()
            .lock()
            .ok()
            .and_then(|mut cache| cache.get_cloned_by(&inode))
    }

    #[cfg(test)]
    pub(crate) fn probe_get_key_cache(key: &str) -> Option<u32> {
        Self::key_cache()
            .lock()
            .ok()
            .and_then(|mut cache| cache.get_cloned_by(key))
    }

    pub fn resolve_pid_by_inode(inode: u32) -> Option<u32> {
        Self::resolve_pid_by_inode_with_key(inode, None)
    }

    pub async fn resolve_pid_by_inode_async(inode: u32) -> Option<u32> {
        tokio::task::spawn_blocking(move || Self::resolve_pid_by_inode(inode))
            .await
            .ok()
            .flatten()
    }

    pub fn enrich_connection_owner(attempt: &mut ConnectionAttempt) {
        let src_ip = attempt.src_addr.to_string();
        let dst_ip = attempt.dst_addr.to_string();

        if let Some(owner) = Self::resolve_owner_by_ebpf_map(
            attempt.protocol,
            &src_ip,
            attempt.src_port,
            &dst_ip,
            attempt.dst_port,
        ) {
            if attempt.uid == 0 {
                attempt.uid = owner.uid;
            }
            if attempt.pid == 0 {
                attempt.pid = owner.pid;
            }
            if attempt.uid != 0 && attempt.pid != 0 {
                return;
            }
        }

        let src = attempt.src_addr;
        let dst = attempt.dst_addr;

        let family = Self::infer_family(attempt);
        let Some(ipproto) = Self::protocol_to_ipproto(attempt.protocol) else {
            return;
        };

        if let Ok(candidates) = SocketDiagAdapter::find_socket_candidates(
            family,
            ipproto,
            src,
            attempt.src_port,
            dst,
            attempt.dst_port,
        ) {
            let lookup_key = Self::inode_lookup_key(
                attempt.protocol,
                &src_ip,
                attempt.src_port,
                &dst_ip,
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

        if let Ok(candidates) = SocketDiagAdapter::find_socket_candidates(
            family,
            ipproto,
            dst,
            attempt.dst_port,
            src,
            attempt.src_port,
        ) {
            let reverse_lookup_key = Self::inode_lookup_key(
                attempt.protocol,
                &dst_ip,
                attempt.dst_port,
                &src_ip,
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

        if let Some(owner) = Self::resolve_owner_by_connection(
            attempt.protocol,
            &src_ip,
            attempt.src_port,
            &dst_ip,
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

    pub async fn enrich_connection_owner_async(attempt: ConnectionAttempt) -> ConnectionAttempt {
        let fallback = attempt.clone();
        tokio::task::spawn_blocking(move || {
            let mut attempt = attempt;
            Self::enrich_connection_owner(&mut attempt);
            attempt
        })
        .await
        .unwrap_or(fallback)
    }

    pub fn resolve_owner_by_connection(
        protocol: TransportProtocol,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        uid_hint: Option<u32>,
    ) -> Option<ConnectionOwner> {
        if let Some(owner) =
            Self::resolve_owner_by_ebpf_map(protocol, src_ip, src_port, dst_ip, dst_port)
        {
            return Some(owner);
        }

        for path in Self::proc_net_paths(protocol) {
            let Ok(contents) = fs::read_to_string(path) else {
                continue;
            };

            for line in contents.lines().skip(1) {
                let Some(((local_ip, local_port), (remote_ip, remote_port), uid, inode)) =
                    Self::parse_proc_net_row(line)
                else {
                    continue;
                };
                if inode == 0 {
                    continue;
                }

                // Keep Go netstat parity: proc row matching is exact 5-tuple only.
                let exact_match = local_ip == src_ip
                    && local_port == src_port
                    && remote_ip == dst_ip
                    && remote_port == dst_port;

                if !exact_match {
                    continue;
                }

                let lookup_key =
                    Self::inode_lookup_key(protocol, src_ip, src_port, dst_ip, dst_port);
                let Some(pid) = Self::resolve_pid_by_inode_with_key(inode, Some(&lookup_key))
                else {
                    continue;
                };

                return Some(ConnectionOwner { uid, pid });
            }
        }

        if let Some(owner) = Self::resolve_owner_from_packet_sockets(protocol, uid_hint) {
            return Some(owner);
        }

        None
    }

    pub fn resolve_owner_by_ebpf_map(
        protocol: TransportProtocol,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<ConnectionOwner> {
        let map_name = Self::bpf_map_name(protocol, src_ip, dst_ip)?;
        let map_id = BpfMapIdCache::global().lock().ok()?.get_map_id(map_name)?;

        let mut key = Self::build_bpf_key(protocol, src_ip, src_port, dst_ip, dst_port)?;
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &key) {
            return Some(ConnectionOwner { uid, pid });
        }

        // See Go behavior: sometimes source address in key is 0.0.0.0/::.
        if key.len() == 12 {
            key[8..12].copy_from_slice(&[0, 0, 0, 0]);
        } else if key.len() == 36 {
            key[20..36].copy_from_slice(&[0; 16]);
        }
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &key) {
            return Some(ConnectionOwner { uid, pid });
        }

        // Keep Go parity: retry by swapping source/destination IP bytes in the key.
        // This can recover ownership for some reverse-flow packet observations.
        let mut swapped = Self::build_bpf_key(protocol, src_ip, src_port, dst_ip, dst_port)?;
        if swapped.len() == 12 {
            let daddr = [swapped[2], swapped[3], swapped[4], swapped[5]];
            let saddr = [swapped[8], swapped[9], swapped[10], swapped[11]];
            swapped[2..6].copy_from_slice(&saddr);
            swapped[8..12].copy_from_slice(&daddr);
        } else if swapped.len() == 36 {
            let mut daddr = [0_u8; 16];
            daddr.copy_from_slice(&swapped[2..18]);
            let mut saddr = [0_u8; 16];
            saddr.copy_from_slice(&swapped[20..36]);
            swapped[2..18].copy_from_slice(&saddr);
            swapped[20..36].copy_from_slice(&daddr);
        }
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &swapped) {
            return Some(ConnectionOwner { uid, pid });
        }

        None
    }
}

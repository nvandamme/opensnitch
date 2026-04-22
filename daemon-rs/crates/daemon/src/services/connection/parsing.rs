use crate::models::{
    connection_owner::ConnectionOwnerCacheKey,
    connection_state::{ConnectionAttempt, TransportProtocol},
};
use nix::libc;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ConnectionService;
use crate::utils::{
    hex_parse::parse_hex_token,
    json_value::find_numeric_for_keys,
};

impl ConnectionService {
    pub(crate) fn extract_ebpf_map_hit_pid_uid(entry: &Value) -> Option<(u32, u32)> {
        let value = entry.get("value").unwrap_or(entry);
        let pid = Self::find_numeric(value, &["pid", "tgid"])? as u32;

        let uid = Self::find_numeric(value, &["uid"])
            .map(|v| v as u32)
            .or_else(|| {
                Self::find_numeric(value, &["uid_gid"]).map(|v| {
                    let lo = v & 0xFFFF_FFFF;
                    lo as u32
                })
            })
            .unwrap_or(0);

        Some((pid, uid))
    }

    pub(crate) fn find_numeric(node: &Value, wanted_keys: &[&str]) -> Option<u64> {
        find_numeric_for_keys(node, wanted_keys)
    }

    pub(super) fn parse_proc_addr_port(value: &str) -> Option<(IpAddr, u16)> {
        let mut parts = value.split(':');
        let addr_hex = parts.next()?;
        let port_hex = parts.next()?;

        let port = parse_hex_token::<u16>(port_hex)?;
        let ip = Self::parse_proc_ip(addr_hex)?;
        Some((ip, port))
    }

    pub(super) fn parse_proc_ip(value: &str) -> Option<IpAddr> {
        if value.len() == 8 {
            let raw = parse_hex_token::<u32>(value)?;
            let b = raw.to_le_bytes();
            return Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
        }

        if value.len() == 32 {
            let mut words = [0_u32; 4];
            for (i, chunk) in value.as_bytes().chunks(8).enumerate() {
                if i >= 4 {
                    return None;
                }
                let chunk = std::str::from_utf8(chunk).ok()?;
                words[i] = parse_hex_token::<u32>(chunk)?;
            }

            let mut octets = [0_u8; 16];
            for (i, word) in words.iter().enumerate() {
                let b = word.to_le_bytes();
                let start = i * 4;
                octets[start..start + 4].copy_from_slice(&b);
            }

            return Some(IpAddr::V6(Ipv6Addr::from(octets)));
        }

        None
    }

    pub(super) fn parse_socket_inode(value: &str) -> Option<u32> {
        if !value.starts_with("socket:[") || !value.ends_with(']') {
            return None;
        }
        value
            .trim_start_matches("socket:[")
            .trim_end_matches(']')
            .parse::<u32>()
            .ok()
    }

    pub(super) fn inode_lookup_key(
        protocol: TransportProtocol,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> ConnectionOwnerCacheKey {
        ConnectionOwnerCacheKey {
            protocol,
            src_addr: src_ip,
            src_port,
            dst_addr: dst_ip,
            dst_port,
        }
    }

    pub(super) fn infer_family(attempt: &ConnectionAttempt) -> u8 {
        match attempt.src_addr {
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
        }
    }

    pub(super) fn protocol_to_ipproto(protocol: TransportProtocol) -> Option<u8> {
        match protocol {
            TransportProtocol::Tcp => Some(libc::IPPROTO_TCP as u8),
            TransportProtocol::Udp => Some(libc::IPPROTO_UDP as u8),
            TransportProtocol::UdpLite => Some(136_u8),
            TransportProtocol::Sctp => Some(132_u8),
            TransportProtocol::Icmp => Some(libc::IPPROTO_RAW as u8),
        }
    }

    pub(super) fn parse_proc_net_row(
        line: &str,
    ) -> Option<((IpAddr, u16), (IpAddr, u16), u32, u32)> {
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

    pub(super) fn proc_net_paths(protocol: TransportProtocol) -> &'static [&'static str] {
        match protocol {
            TransportProtocol::Tcp => &["/proc/net/tcp", "/proc/net/tcp6"],
            TransportProtocol::Udp => &["/proc/net/udp", "/proc/net/udp6"],
            TransportProtocol::UdpLite => &["/proc/net/udplite", "/proc/net/udplite6"],
            TransportProtocol::Sctp => &["/proc/net/sctp/eps", "/proc/net/sctp/assocs"],
            TransportProtocol::Icmp => &["/proc/net/icmp", "/proc/net/icmp6"],
        }
    }

    pub(super) fn parse_value_hex_bytes(value: &str) -> Option<Vec<u8>> {
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
                let normalized = tok.trim_start_matches("0x");
                if normalized.len() != 2 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                if let Some(v) = parse_hex_token::<u8>(normalized) {
                    out.push(v);
                }
            }
        }

        if out.is_empty() { None } else { Some(out) }
    }
}

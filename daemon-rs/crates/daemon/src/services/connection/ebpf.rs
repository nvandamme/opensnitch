use crate::models::{connection_owner::ConnectionOwner, connection_state::TransportProtocol};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use super::ConnectionService;

static BPF_MAP_IDS: OnceLock<Mutex<BpfMapIdCache>> = OnceLock::new();

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

        let parsed: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
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

impl ConnectionService {
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

        let text = String::from_utf8_lossy(&out.stdout).to_string();
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

    pub(super) fn resolve_owner_by_ebpf_map(
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

        if key.len() == 12 {
            key[8..12].copy_from_slice(&[0, 0, 0, 0]);
        } else if key.len() == 36 {
            key[20..36].copy_from_slice(&[0; 16]);
        }
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &key) {
            return Some(ConnectionOwner { uid, pid });
        }

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

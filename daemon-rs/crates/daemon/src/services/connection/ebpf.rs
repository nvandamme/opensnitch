use crate::models::{connection_owner::ConnectionOwner, connection_state::TransportProtocol};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    ops::{Deref, DerefMut},
};

use super::ConnectionService;

/// Stack-allocated eBPF map key — 12 bytes for IPv4 connections, 36 bytes
/// for IPv6.  Avoids a `Vec<u8>` heap allocation (one per lookup attempt)
/// on the kernel event hot path.
enum BpfKey {
    V4([u8; 12]),
    V6([u8; 36]),
}

impl Deref for BpfKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            BpfKey::V4(arr) => arr,
            BpfKey::V6(arr) => arr,
        }
    }
}

impl DerefMut for BpfKey {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            BpfKey::V4(arr) => arr,
            BpfKey::V6(arr) => arr,
        }
    }
}

/// Enumerate loaded eBPF maps and return a fresh name → kernel-id table.
///
/// Priority order: aya (`loaded_maps()`) → libbpf-rs (`MapInfoIter`).
/// Returns an empty map when both eBPF crates are disabled (CI/dev builds).
pub(super) fn list_bpf_maps() -> HashMap<String, u32> {
    #[cfg(feature = "aya-ebpf")]
    {
        let mut by_name = HashMap::new();
        for info in aya::maps::loaded_maps().flatten() {
            if let Some(name) = info.name_as_str() {
                by_name.insert(name.to_string(), info.id());
            }
        }
        return by_name;
    }

    #[cfg(all(not(feature = "aya-ebpf"), feature = "libbpf-ebpf"))]
    {
        use libbpf_rs::query::MapInfoIter;
        let mut by_name = HashMap::new();
        for info in MapInfoIter::default() {
            by_name.insert(info.name.to_string_lossy().into_owned(), info.id);
        }
        return by_name;
    }

    // Both eBPF crates disabled: no eBPF maps available.
    #[allow(unreachable_code)]
    HashMap::new()
}

impl ConnectionService {
    fn bpf_map_name(
        protocol: TransportProtocol,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Option<&'static str> {
        let is_ipv6 = src_ip.is_ipv6() || dst_ip.is_ipv6();
        match protocol {
            TransportProtocol::Tcp => Some(if is_ipv6 { "tcpv6Map" } else { "tcpMap" }),
            TransportProtocol::Udp | TransportProtocol::UdpLite => {
                Some(if is_ipv6 { "udpv6Map" } else { "udpMap" })
            }
            TransportProtocol::Sctp | TransportProtocol::Icmp => None,
        }
    }

    fn build_bpf_key(
        protocol: TransportProtocol,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<BpfKey> {
        match protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp | TransportProtocol::UdpLite => {
                if src_ip.is_ipv6() || dst_ip.is_ipv6() {
                    let src = match src_ip {
                        IpAddr::V6(v6) => v6.octets(),
                        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                    };
                    let dst = match dst_ip {
                        IpAddr::V6(v6) => v6.octets(),
                        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                    };
                    let mut arr = [0_u8; 36];
                    arr[0..2].copy_from_slice(&src_port.to_ne_bytes());
                    arr[2..18].copy_from_slice(&dst);
                    arr[18..20].copy_from_slice(&dst_port.to_be_bytes());
                    arr[20..36].copy_from_slice(&src);
                    Some(BpfKey::V6(arr))
                } else {
                    let src = match src_ip {
                        IpAddr::V4(v4) => v4.octets(),
                        IpAddr::V6(v6) => v6.to_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED).octets(),
                    };
                    let dst = match dst_ip {
                        IpAddr::V4(v4) => v4.octets(),
                        IpAddr::V6(v6) => v6.to_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED).octets(),
                    };
                    let mut arr = [0_u8; 12];
                    arr[0..2].copy_from_slice(&src_port.to_ne_bytes());
                    arr[2..6].copy_from_slice(&dst);
                    arr[6..8].copy_from_slice(&dst_port.to_be_bytes());
                    arr[8..12].copy_from_slice(&src);
                    Some(BpfKey::V4(arr))
                }
            }
            TransportProtocol::Sctp | TransportProtocol::Icmp => None,
        }
    }

    /// Look up the eBPF map entry for `key` in the map identified by `map_id` and
    /// return `(pid, uid)` if found.
    ///
    /// Priority order: aya (`MapData::from_id` + typed [`HashMap`] lookup) →
    /// libbpf-rs (`MapHandle::from_map_id` + `MapCore::lookup`).
    /// Returns `None` when both eBPF crates are disabled.
    fn lookup_bpf_owner(map_id: u32, key: &[u8]) -> Option<(u32, u32)> {
        #[cfg(feature = "aya-ebpf")]
        if let Some(result) = Self::aya_lookup_bpf_owner(map_id, key) {
            return Some(result);
        }

        #[cfg(feature = "libbpf-ebpf")]
        {
            use libbpf_rs::{MapCore, MapFlags, MapHandle};
            let map = MapHandle::from_map_id(map_id).ok()?;
            let value_bytes = map.lookup(key, MapFlags::empty()).ok()??;
            if value_bytes.len() < 16 {
                return None;
            }
            let pid = u64::from_ne_bytes(value_bytes[0..8].try_into().ok()?) as u32;
            let uid = u64::from_ne_bytes(value_bytes[8..16].try_into().ok()?) as u32;
            return Some((pid, uid));
        }

        // Both eBPF crates disabled: owner unknown.
        None
    }

    /// Direct eBPF map lookup via aya typed [`HashMap`] API.
    ///
    /// Dispatches on key length: 12 bytes (IPv4) or 36 bytes (IPv6).  The value layout
    /// is always 16 bytes: `pid: u64` at bytes [0..8], `uid: u64` at bytes [8..16].
    #[cfg(feature = "aya-ebpf")]
    fn aya_lookup_bpf_owner(map_id: u32, key: &[u8]) -> Option<(u32, u32)> {
        use aya::maps::{HashMap as AyaHashMap, Map, MapData};

        fn decode_pid_uid(bytes: &[u8; 16]) -> (u32, u32) {
            let pid = u64::from_ne_bytes(bytes[0..8].try_into().unwrap()) as u32;
            let uid = u64::from_ne_bytes(bytes[8..16].try_into().unwrap()) as u32;
            (pid, uid)
        }

        match key.len() {
            12 => {
                let key_arr: [u8; 12] = key.try_into().ok()?;
                let map_data = MapData::from_id(map_id).ok()?;
                let map: AyaHashMap<_, [u8; 12], [u8; 16]> =
                    Map::HashMap(map_data).try_into().ok()?;
                let value = map.get(&key_arr, 0).ok()?;
                Some(decode_pid_uid(&value))
            }
            36 => {
                let key_arr: [u8; 36] = key.try_into().ok()?;
                let map_data = MapData::from_id(map_id).ok()?;
                let map: AyaHashMap<_, [u8; 36], [u8; 16]> =
                    Map::HashMap(map_data).try_into().ok()?;
                let value = map.get(&key_arr, 0).ok()?;
                Some(decode_pid_uid(&value))
            }
            _ => None,
        }
    }

    pub(super) fn resolve_owner_by_ebpf_map(
        &self,
        protocol: TransportProtocol,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<ConnectionOwner> {
        let map_name = Self::bpf_map_name(protocol, src_ip, dst_ip)?;
        let map_id = self.bpf_map_snapshot().load().get(map_name).copied()?;

        let mut key = Self::build_bpf_key(protocol, src_ip, src_port, dst_ip, dst_port)?;
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &key) {
            return Some(ConnectionOwner { uid, pid });
        }

        match &mut key {
            BpfKey::V4(arr) => arr[8..12].fill(0),
            BpfKey::V6(arr) => arr[20..36].fill(0),
        }
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &key) {
            return Some(ConnectionOwner { uid, pid });
        }

        let mut swapped = Self::build_bpf_key(protocol, src_ip, src_port, dst_ip, dst_port)?;
        match &mut swapped {
            BpfKey::V4(arr) => {
                let daddr = [arr[2], arr[3], arr[4], arr[5]];
                let saddr = [arr[8], arr[9], arr[10], arr[11]];
                arr[2..6].copy_from_slice(&saddr);
                arr[8..12].copy_from_slice(&daddr);
            }
            BpfKey::V6(arr) => {
                let mut daddr = [0_u8; 16];
                daddr.copy_from_slice(&arr[2..18]);
                let mut saddr = [0_u8; 16];
                saddr.copy_from_slice(&arr[20..36]);
                arr[2..18].copy_from_slice(&saddr);
                arr[20..36].copy_from_slice(&daddr);
            }
        }
        if let Some((pid, uid)) = Self::lookup_bpf_owner(map_id, &swapped) {
            return Some(ConnectionOwner { uid, pid });
        }

        None
    }
}


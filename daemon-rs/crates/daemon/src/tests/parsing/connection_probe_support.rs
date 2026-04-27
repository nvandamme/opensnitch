use std::net::IpAddr;
use std::sync::atomic::Ordering;

use crate::{
    models::{connection::owner::ConnectionOwnerCacheKey, connection::state::TransportProtocol},
    services::connection::ConnectionService,
};

use super::runtime_lifecycle::{INODE_KEY_TO_PID_CACHE_CAPACITY, INODE_TO_PID_CACHE_CAPACITY};

impl ConnectionService {
    pub(crate) fn probe_parse_proc_addr_port(value: &str) -> Option<(IpAddr, u16)> {
        Self::parse_proc_addr_port(value)
    }

    pub(crate) fn probe_parse_proc_ip(value: &str) -> Option<IpAddr> {
        Self::parse_proc_ip(value)
    }

    pub(crate) fn probe_parse_socket_inode(value: &str) -> Option<u32> {
        Self::parse_socket_inode(value)
    }

    pub(crate) fn probe_parse_value_hex_bytes(value: &str) -> Option<Vec<u8>> {
        Self::parse_value_hex_bytes(value)
    }

    pub(crate) fn probe_protocol_to_ipproto(protocol: TransportProtocol) -> Option<u8> {
        Self::protocol_to_ipproto(protocol)
    }

    pub(crate) fn probe_cache_capacities() -> (usize, usize) {
        (
            INODE_TO_PID_CACHE_CAPACITY.load(Ordering::Relaxed),
            INODE_KEY_TO_PID_CACHE_CAPACITY.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn probe_reset_caches() {
        Self::cache().clear();
        Self::key_cache().clear();
    }

    pub(crate) fn probe_insert_inode_cache(inode: u32, pid: u32) {
        Self::cache().insert(inode, pid);
    }

    pub(crate) fn probe_insert_key_cache(key: ConnectionOwnerCacheKey, pid: u32) {
        Self::key_cache().insert(key, pid);
    }

    pub(crate) fn probe_inode_cache_len() -> usize {
        Self::cache().len()
    }

    pub(crate) fn probe_key_cache_len() -> usize {
        Self::key_cache().len()
    }

    pub(crate) fn probe_get_inode_cache(inode: u32) -> Option<u32> {
        Self::cache().get(&inode)
    }

    pub(crate) fn probe_get_key_cache(key: ConnectionOwnerCacheKey) -> Option<u32> {
        Self::key_cache().get(&key)
    }
}

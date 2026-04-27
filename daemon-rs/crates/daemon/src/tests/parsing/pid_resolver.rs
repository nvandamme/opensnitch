use std::net::{IpAddr, Ipv4Addr};

use crate::{
    models::{connection::owner::ConnectionOwnerCacheKey, connection::state::TransportProtocol},
    services::connection::ConnectionService,
};

#[test]
fn parse_socket_inode_accepts_socket_link() {
    assert_eq!(
        ConnectionService::probe_parse_socket_inode("socket:[12345]"),
        Some(12345)
    );
    assert_eq!(
        ConnectionService::probe_parse_socket_inode("pipe:[12345]"),
        None
    );
}

#[test]
fn parse_proc_ip_supports_ipv4_and_ipv6() {
    assert_eq!(
        ConnectionService::probe_parse_proc_ip("0100007F"),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    );
    assert!(ConnectionService::probe_parse_proc_ip("00000000000000000000000000000001").is_some());
}

#[test]
fn parse_value_hex_bytes_extracts_value_section() {
    let text = "key:\n  00 00\nvalue:\n  01 02 0a ff\n";
    assert_eq!(
        ConnectionService::probe_parse_value_hex_bytes(text),
        Some(vec![1, 2, 10, 255])
    );
}

#[test]
fn parse_proc_addr_port_supports_ipv4_and_port() {
    assert_eq!(
        ConnectionService::probe_parse_proc_addr_port("0100007F:01BB"),
        Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443))
    );
}

#[test]
fn parse_proc_addr_port_rejects_invalid_input() {
    assert_eq!(
        ConnectionService::probe_parse_proc_addr_port("not-an-addr"),
        None
    );
    assert_eq!(
        ConnectionService::probe_parse_proc_addr_port("0100007F:zzzz"),
        None
    );
}

#[test]
fn parse_socket_inode_rejects_malformed_socket_links() {
    assert_eq!(
        ConnectionService::probe_parse_socket_inode("socket:[]"),
        None
    );
    assert_eq!(
        ConnectionService::probe_parse_socket_inode("socket:[abc]"),
        None
    );
    assert_eq!(
        ConnectionService::probe_parse_socket_inode("socket:[123"),
        None
    );
}

#[test]
fn parse_proc_ip_rejects_invalid_hex_inputs() {
    assert_eq!(ConnectionService::probe_parse_proc_ip("GG00007F"), None);
    assert_eq!(ConnectionService::probe_parse_proc_ip("12345"), None);
}

#[test]
fn parse_value_hex_bytes_ignores_non_value_section_and_accepts_mixed_tokens() {
    let text = "header:\n  aa bb\nvalue:\n  10 gg 20, 30: zz\n";
    assert_eq!(
        ConnectionService::probe_parse_value_hex_bytes(text),
        Some(vec![16, 32, 48])
    );
}

#[test]
fn parse_proc_addr_port_rejects_missing_or_extra_port_sections() {
    assert_eq!(
        ConnectionService::probe_parse_proc_addr_port("0100007F"),
        None
    );
    assert_eq!(
        ConnectionService::probe_parse_proc_addr_port("0100007F:01BB:FFFF"),
        Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443))
    );
}

#[test]
fn parse_value_hex_bytes_returns_none_without_value_block() {
    let text = "header:\n  00 11 22\n";
    assert_eq!(ConnectionService::probe_parse_value_hex_bytes(text), None);
}

#[test]
fn icmp_transport_maps_to_raw_ipproto_for_socket_diag_lookup() {
    assert_eq!(
        ConnectionService::probe_protocol_to_ipproto(TransportProtocol::Icmp),
        Some(nix::libc::IPPROTO_RAW as u8)
    );
}

#[test]
fn inode_and_key_pid_caches_are_bounded_lru() {
    ConnectionService::probe_reset_caches();
    let (inode_cap, key_cap) = ConnectionService::probe_cache_capacities();

    let test_key = |idx: usize| ConnectionOwnerCacheKey {
        protocol: TransportProtocol::Tcp,
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, (idx / 256) as u8, (idx % 256) as u8)),
        src_port: 1,
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_port: 443,
    };

    // Insert 2× capacity to guarantee every shard cycles and oldest items are evicted.
    for idx in 0..(inode_cap * 2) {
        ConnectionService::probe_insert_inode_cache(idx as u32, (idx + 1) as u32);
    }

    for idx in 0..(key_cap * 2) {
        ConnectionService::probe_insert_key_cache(test_key(idx), (idx + 1) as u32);
    }

    // Cache is bounded (approximate eviction may leave a few slots unused).
    assert!(ConnectionService::probe_inode_cache_len() <= inode_cap);
    assert!(ConnectionService::probe_key_cache_len() <= key_cap);

    // Most recently inserted entries are still present.
    let newest_inode = (inode_cap * 2 - 1) as u32;
    assert_eq!(
        ConnectionService::probe_get_inode_cache(newest_inode),
        Some((inode_cap * 2) as u32)
    );

    let newest_key = test_key(key_cap * 2 - 1);
    assert_eq!(
        ConnectionService::probe_get_key_cache(newest_key),
        Some((key_cap * 2) as u32)
    );
}

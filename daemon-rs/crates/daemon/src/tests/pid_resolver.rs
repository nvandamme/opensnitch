use crate::utils::pid_resolver::ResolverTextExt;
use crate::{
    models::connection_state::TransportProtocol, utils::pid_resolver::ipproto_for_transport,
};

#[test]
fn parse_socket_inode_accepts_socket_link() {
    assert_eq!("socket:[12345]".parse_socket_inode(), Some(12345));
    assert_eq!("pipe:[12345]".parse_socket_inode(), None);
}

#[test]
fn parse_proc_ip_supports_ipv4_and_ipv6() {
    assert_eq!("0100007F".parse_proc_ip(), Some("127.0.0.1".to_string()));
    assert!("00000000000000000000000000000001".parse_proc_ip().is_some());
}

#[test]
fn parse_value_hex_bytes_extracts_value_section() {
    let text = "key:\n  00 00\nvalue:\n  01 02 0a ff\n";
    assert_eq!(text.parse_value_hex_bytes(), Some(vec![1, 2, 10, 255]));
}

#[test]
fn parse_proc_addr_port_supports_ipv4_and_port() {
    assert_eq!(
        "0100007F:01BB".parse_proc_addr_port(),
        Some(("127.0.0.1".to_string(), 443))
    );
}

#[test]
fn parse_proc_addr_port_rejects_invalid_input() {
    assert_eq!("not-an-addr".parse_proc_addr_port(), None);
    assert_eq!("0100007F:zzzz".parse_proc_addr_port(), None);
}

#[test]
fn parse_socket_inode_rejects_malformed_socket_links() {
    assert_eq!("socket:[]".parse_socket_inode(), None);
    assert_eq!("socket:[abc]".parse_socket_inode(), None);
    assert_eq!("socket:[123".parse_socket_inode(), None);
}

#[test]
fn parse_proc_ip_rejects_invalid_hex_inputs() {
    assert_eq!("GG00007F".parse_proc_ip(), None);
    assert_eq!("12345".parse_proc_ip(), None);
}

#[test]
fn parse_value_hex_bytes_ignores_non_value_section_and_accepts_mixed_tokens() {
    let text = "header:\n  aa bb\nvalue:\n  10 gg 20, 30: zz\n";
    assert_eq!(text.parse_value_hex_bytes(), Some(vec![16, 32, 48]));
}

#[test]
fn parse_proc_addr_port_rejects_missing_or_extra_port_sections() {
    assert_eq!("0100007F".parse_proc_addr_port(), None);
    assert_eq!(
        "0100007F:01BB:FFFF".parse_proc_addr_port(),
        Some(("127.0.0.1".to_string(), 443))
    );
}

#[test]
fn parse_value_hex_bytes_returns_none_without_value_block() {
    let text = "header:\n  00 11 22\n";
    assert_eq!(text.parse_value_hex_bytes(), None);
}

#[test]
fn icmp_transport_maps_to_raw_ipproto_for_socket_diag_lookup() {
    assert_eq!(
        ipproto_for_transport(TransportProtocol::Icmp),
        Some(nix::libc::IPPROTO_RAW as u8)
    );
}

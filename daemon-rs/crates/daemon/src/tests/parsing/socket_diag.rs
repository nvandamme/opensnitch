use crate::platform::netstat::socket_diag::SocketDiagAdapter;
use crate::platform::netstat::socket_state::SocketInfo;
use nix::libc::{AF_INET, IPPROTO_TCP};

#[test]
fn build_kill_req_v2_preserves_socket_identity() {
    let socket = SocketInfo {
        family: AF_INET as u8,
        state: 0,
        timer: 0,
        retrans: 0,
        src_port: 4242,
        dst_port: 443,
        src: "10.1.1.2".parse().expect("valid source ip"),
        dst: "1.1.1.1".parse().expect("valid destination ip"),
        expires: 0,
        rqueue: 0,
        wqueue: 0,
        uid: 0,
        inode: 0,
        iface: 3,
        mark: 0,
        cookie0: 0x11223344,
        cookie1: 0xaabbccdd,
    };

    let req = SocketDiagAdapter::probe_build_kill_req_v2(AF_INET as u8, IPPROTO_TCP as u8, &socket);

    assert_eq!(req.family, AF_INET as u8);
    assert_eq!(req.protocol, IPPROTO_TCP as u8);
    assert_eq!(req.sockid.sport(), 4242);
    assert_eq!(req.sockid.dport(), 443);
    assert_eq!(req.sockid.r#if, 3);
    assert_eq!(
        SocketDiagAdapter::probe_decode_cookie_words(req.sockid.cookie),
        (0x11223344, 0xaabbccdd)
    );
}

#[test]
fn decode_cookie_round_trip_matches_input_words() {
    let socket = SocketInfo {
        family: AF_INET as u8,
        state: 0,
        timer: 0,
        retrans: 0,
        src_port: 0,
        dst_port: 0,
        src: "0.0.0.0".parse().expect("valid wildcard source ip"),
        dst: "0.0.0.0".parse().expect("valid wildcard destination ip"),
        expires: 0,
        rqueue: 0,
        wqueue: 0,
        uid: 0,
        inode: 0,
        iface: 0,
        mark: 0,
        cookie0: 0x01020304,
        cookie1: 0xa0b0c0d0,
    };

    assert_eq!(
        SocketDiagAdapter::probe_decode_cookie_words(SocketDiagAdapter::probe_socket_cookie_bytes(
            &socket,
        )),
        (0x01020304, 0xa0b0c0d0)
    );
}

#[test]
fn candidate_selection_prefers_exact_then_wildcard_fallbacks() {
    let exact = SocketInfo {
        family: AF_INET as u8,
        state: 0,
        timer: 0,
        retrans: 0,
        src_port: 5555,
        dst_port: 443,
        src: "10.0.0.2".parse().expect("valid src ip"),
        dst: "1.1.1.1".parse().expect("valid dst ip"),
        expires: 0,
        rqueue: 0,
        wqueue: 0,
        uid: 1000,
        inode: 10,
        iface: 0,
        mark: 0,
        cookie0: 0,
        cookie1: 0,
    };

    let wildcard = SocketInfo {
        inode: 11,
        dst_port: 0,
        dst: "0.0.0.0".parse().expect("valid wildcard ip"),
        ..exact.clone()
    };

    let port_only = SocketInfo {
        inode: 12,
        dst: "203.0.113.10".parse().expect("valid fallback ip"),
        ..exact.clone()
    };

    let candidates = SocketDiagAdapter::probe_select_socket_candidates(
        &[wildcard.clone(), port_only.clone(), exact.clone()],
        exact.src,
        exact.src_port,
        exact.dst,
        exact.dst_port,
    );

    assert_eq!(candidates[0].inode, exact.inode);
    assert!(candidates.iter().any(|s| s.inode == wildcard.inode));
    assert!(candidates.iter().any(|s| s.inode == port_only.inode));
}

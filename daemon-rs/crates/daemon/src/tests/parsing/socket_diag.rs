use crate::models::socket_state::SocketInfo;
use crate::platform::adapters::socket_diag::SocketDiagAdapter;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkPayload};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::{AF_INET, IPPROTO_TCP, SOCK_DESTROY},
};

#[test]
fn build_destroy_request_uses_sock_destroy_and_preserves_socket_identity() {
    let socket = SocketInfo {
        family: AF_INET,
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

    let msg = SocketDiagAdapter::probe_build_destroy_message(AF_INET, IPPROTO_TCP, &socket);

    assert_eq!(msg.header.message_type, SOCK_DESTROY);
    assert_eq!(msg.header.flags & NLM_F_REQUEST, NLM_F_REQUEST);
    assert_eq!(msg.header.flags & NLM_F_ACK, NLM_F_ACK);

    let NetlinkPayload::InnerMessage(SockDiagMessage::InetRequest(ref req)) = msg.payload else {
        panic!("expected inet destroy request payload");
    };

    assert_eq!(req.family, AF_INET);
    assert_eq!(req.protocol, IPPROTO_TCP);
    assert_eq!(req.socket_id.source_port, 4242);
    assert_eq!(req.socket_id.destination_port, 443);
    assert_eq!(req.socket_id.interface_id, 3);
    assert_eq!(req.socket_id.source_address, socket.src);
    assert_eq!(req.socket_id.destination_address, socket.dst);
    assert_eq!(
        SocketDiagAdapter::probe_decode_cookie_words(req.socket_id.cookie),
        (0x11223344, 0xaabbccdd)
    );

    let mut bytes = vec![0_u8; msg.buffer_len()];
    msg.serialize(&mut bytes);
    assert!(!bytes.is_empty());
    assert_eq!(bytes.len(), msg.buffer_len());
}

#[test]
fn decode_cookie_round_trip_matches_input_words() {
    let socket = SocketInfo {
        family: AF_INET,
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
        family: AF_INET,
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

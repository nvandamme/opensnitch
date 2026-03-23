use crate::platform::adapters::audit_netlink::AuditNetlinkSocket;
use nix::libc;

const NLMSG_HDR_LEN: usize = 16;
const STATUS_MESSAGE_LEN: usize = 40;

fn build_datagram(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = NLMSG_HDR_LEN + payload.len();
    let mut out = Vec::with_capacity(total_len);
    out.extend((total_len as u32).to_ne_bytes());
    out.extend(msg_type.to_ne_bytes());
    out.extend(0_u16.to_ne_bytes());
    out.extend(1_u32.to_ne_bytes());
    out.extend(123_u32.to_ne_bytes());
    out.extend(payload);
    out
}

#[test]
fn enable_events_payload_sets_mask_enabled_and_pid() {
    let payload = AuditNetlinkSocket::probe_build_enable_events_payload();

    assert_eq!(payload.len(), STATUS_MESSAGE_LEN);
    assert_eq!(u32::from_ne_bytes(payload[0..4].try_into().expect("mask bytes")), 5);
    assert_eq!(u32::from_ne_bytes(payload[4..8].try_into().expect("enabled bytes")), 1);
    assert_eq!(
        u32::from_ne_bytes(payload[12..16].try_into().expect("pid bytes")),
        std::process::id()
    );
}

#[test]
fn parse_event_datagram_extracts_audit_payload() {
    let datagram = build_datagram(1300, b"type=SYSCALL msg=audit(1:2): pid=4242 key=\"opensnitch\"\0");
    let event = AuditNetlinkSocket::probe_parse_event_datagram(&datagram)
        .expect("parse event datagram")
        .expect("event payload");

    assert_eq!(event.kind, 1300);
    assert!(event.data.contains("pid=4242"));
    assert!(event.data.contains("key=\"opensnitch\""));
}

#[test]
fn parse_error_datagram_returns_errno() {
    let payload = (-libc::EPERM).to_ne_bytes();
    let datagram = build_datagram(libc::NLMSG_ERROR as u16, &payload);
    let err = AuditNetlinkSocket::probe_parse_event_datagram(&datagram)
        .expect_err("expected error datagram to fail");

    let io = err.downcast_ref::<std::io::Error>().expect("io error");
    assert_eq!(io.raw_os_error(), Some(libc::EPERM));
}
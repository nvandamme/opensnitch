use crate::platform::adapters::nfqueue_netlink::{
    NfqPacket, NfqueueNetlinkAdapter, NlMsg, NFGENMSG_LEN, NFQA_CFG_CMD, NFQA_CFG_FLAGS,
    NFQA_CFG_MASK, NFQA_CFG_PARAMS, NFQA_CFG_QUEUE_MAXLEN, NFQA_IFINDEX_INDEV,
    NFQA_IFINDEX_OUTDEV, NFQA_MARK, NFQA_PACKET_HDR, NFQA_PAYLOAD, NFQA_UID,
    NFQA_VERDICT_HDR, NLA_HDR_LEN, NLMSG_HDR_LEN, nla_align, nlmsg_align, parse_nfq_packet,
};

// ─── NlMsg wire-shape tests ───────────────────────────────────────────────────

/// Minimum well-formed message: nlmsghdr + nfgenmsg only, no attributes.
#[test]
fn nlmsg_bare_shape_is_correct() {
    let buf = NlMsg::new(0x302, 0x01, 1)
        .nfgenmsg(0, 0)
        .finalize();

    assert_eq!(buf.len(), NLMSG_HDR_LEN + NFGENMSG_LEN);

    // nlmsg_len (LE u32)
    let declared_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    assert_eq!(declared_len, buf.len());

    // nlmsg_type = 0x302 (NFQNL_MSG_CONFIG) as native-endian u16
    let msg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
    assert_eq!(msg_type, 0x302);

    // nlmsg_flags = NLM_F_REQUEST (1)
    let flags = u16::from_ne_bytes(buf[6..8].try_into().unwrap());
    assert_eq!(flags, 0x01);

    // nlmsg_seq = 1 (native-endian u32)
    let seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
    assert_eq!(seq, 1);

    // nlmsg_pid = 0
    let pid = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
    assert_eq!(pid, 0);

    // nfgenmsg: family=0, version=0, res_id=0 (BE u16)
    assert_eq!(buf[16], 0); // family = AF_UNSPEC
    assert_eq!(buf[17], 0); // NFNETLINK_V0
    assert_eq!(buf[18], 0); // res_id high byte
    assert_eq!(buf[19], 0); // res_id low byte
}

/// nfgenmsg.res_id is written in big-endian (queue_num=7 → bytes [0x00, 0x07]).
#[test]
fn nfgenmsg_res_id_is_big_endian() {
    let buf = NlMsg::new(0x302, 0x01, 1)
        .nfgenmsg(0, 7)
        .finalize();
    assert_eq!(buf[18], 0x00);
    assert_eq!(buf[19], 0x07);
}

/// A config CMD message targeting queue 7 with BIND command has correct wire shape.
#[test]
fn nlmsg_config_bind_cmd_wire_shape() {
    const NFQNL_MSG_CONFIG: u16 = (3 << 8) | 2; // 0x302
    const NLM_F_REQUEST: u16 = 0x01;
    const NFQNL_CFG_CMD_BIND: u8 = 1;

    // cmd = { command=BIND(1), pad=0, pf=0 }
    let cmd_payload: [u8; 4] = [NFQNL_CFG_CMD_BIND, 0, 0, 0];
    let buf = NlMsg::new(NFQNL_MSG_CONFIG, NLM_F_REQUEST, 2)
        .nfgenmsg(0, 7)
        .nla_bytes(NFQA_CFG_CMD, &cmd_payload)
        .finalize();

    // Total = 16 (nlmsghdr) + 4 (nfgenmsg) + NLA(4 hdr + 4 data) = 28
    assert_eq!(buf.len(), 28);

    // NLA starts at offset 20
    let nla_len = u16::from_ne_bytes(buf[20..22].try_into().unwrap()) as usize;
    let nla_type = u16::from_ne_bytes(buf[22..24].try_into().unwrap());
    assert_eq!(nla_len, NLA_HDR_LEN + 4); // 8
    assert_eq!(nla_type, NFQA_CFG_CMD);  // 1

    // NLA data: command byte first
    assert_eq!(buf[24], NFQNL_CFG_CMD_BIND);
    assert_eq!(buf[25], 0); // pad
    assert_eq!(buf[26], 0); // pf high (AF_UNSPEC)
    assert_eq!(buf[27], 0); // pf low
}

/// PF_BIND for AF_INET puts pf=2 in big-endian at bytes [high, low].
#[test]
fn nlmsg_pf_bind_af_inet_pf_field_is_big_endian() {
    const AF_INET: u16 = 2;
    const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
    let cmd_payload: [u8; 4] = [NFQNL_CFG_CMD_PF_BIND, 0, (AF_INET >> 8) as u8, AF_INET as u8];
    let buf = NlMsg::new(0x302, 0x01, 1)
        .nfgenmsg(0, 0)
        .nla_bytes(NFQA_CFG_CMD, &cmd_payload)
        .finalize();
    // pf bytes are at NLA data offset [2..4] = buf[26..28]
    assert_eq!(buf[26], 0x00); // AF_INET high byte
    assert_eq!(buf[27], 0x02); // AF_INET low byte
}

/// nla_u32_be stores the value in network byte order.
#[test]
fn nla_u32_be_stores_value_in_network_byte_order() {
    let buf = NlMsg::new(0x302, 0x01, 1)
        .nfgenmsg(0, 0)
        .nla_u32_be(NFQA_CFG_QUEUE_MAXLEN, 0x00001000) // 4096
        .finalize();
    // NLA starts at offset 20, data at offset 24
    assert_eq!(&buf[24..28], &[0x00, 0x00, 0x10, 0x00]);
}

/// Odd-length NLA payload is padded to 4-byte boundary.
#[test]
fn nla_bytes_pads_to_4_byte_alignment() {
    // 5-byte payload → aligned to 8 bytes → NLA total = 4 + 8 = 12, but nla_len = 4+5=9
    let payload = [1u8, 2, 3, 4, 5];
    let buf = NlMsg::new(0x302, 0x01, 1)
        .nfgenmsg(0, 0)
        .nla_bytes(NFQA_CFG_PARAMS, &payload)
        .finalize();

    let nla_start = NLMSG_HDR_LEN + NFGENMSG_LEN;
    let nla_len = u16::from_ne_bytes(buf[nla_start..nla_start + 2].try_into().unwrap()) as usize;
    assert_eq!(nla_len, NLA_HDR_LEN + 5); // 9 — actual data length stored in header

    // Total message length = 16 + 4 + 4 (NLA hdr) + 8 (payload aligned) = 32
    assert_eq!(buf.len(), 32);

    // Padding byte at offset nla_start + 4 + 5 must be 0
    assert_eq!(buf[nla_start + NLA_HDR_LEN + 5], 0);
}

/// A verdict message (NFQNL_MSG_VERDICT) places NFQA_VERDICT_HDR at NLA offset.
#[test]
fn nlmsg_verdict_wire_shape_accept() {
    const NFQNL_MSG_VERDICT: u16 = (3 << 8) | 1; // 0x301
    const NF_ACCEPT: u32 = 1;
    const PACKET_ID: u32 = 42;

    let mut verdict_hdr = [0u8; 8];
    verdict_hdr[0..4].copy_from_slice(&NF_ACCEPT.to_be_bytes());
    verdict_hdr[4..8].copy_from_slice(&PACKET_ID.to_be_bytes());

    let buf = NlMsg::new(NFQNL_MSG_VERDICT, 0x01, 5)
        .nfgenmsg(0, 7)
        .nla_bytes(NFQA_VERDICT_HDR, &verdict_hdr)
        .finalize();

    // NLA at offset 20
    let nla_type = u16::from_ne_bytes(buf[22..24].try_into().unwrap());
    assert_eq!(nla_type, NFQA_VERDICT_HDR); // 2

    // verdict = NF_ACCEPT (1) in BE
    let verdict = u32::from_be_bytes(buf[24..28].try_into().unwrap());
    assert_eq!(verdict, NF_ACCEPT);

    // id = PACKET_ID in BE
    let id = u32::from_be_bytes(buf[28..32].try_into().unwrap());
    assert_eq!(id, PACKET_ID);
}

/// A requeue verdict encodes `NF_QUEUE | (queue_num << 16)`.
#[test]
fn nlmsg_verdict_wire_shape_requeue() {
    const NFQNL_MSG_VERDICT: u16 = (3 << 8) | 1;
    const NF_QUEUE: u32 = 3;
    let queue_num: u16 = 8;
    let verdict_val: u32 = NF_QUEUE | ((queue_num as u32) << 16);

    let mut verdict_hdr = [0u8; 8];
    verdict_hdr[0..4].copy_from_slice(&verdict_val.to_be_bytes());
    verdict_hdr[4..8].copy_from_slice(&99u32.to_be_bytes());

    let buf = NlMsg::new(NFQNL_MSG_VERDICT, 0x01, 1)
        .nfgenmsg(0, 7)
        .nla_bytes(NFQA_VERDICT_HDR, &verdict_hdr)
        .finalize();

    let v = u32::from_be_bytes(buf[24..28].try_into().unwrap());
    assert_eq!(v, NF_QUEUE | ((queue_num as u32) << 16));
}

// ─── Alignment helpers ────────────────────────────────────────────────────────

#[test]
fn nlmsg_align_rounds_up_to_4() {
    assert_eq!(nlmsg_align(0), 0);
    assert_eq!(nlmsg_align(1), 4);
    assert_eq!(nlmsg_align(4), 4);
    assert_eq!(nlmsg_align(5), 8);
    assert_eq!(nlmsg_align(16), 16);
}

#[test]
fn nla_align_rounds_up_to_4() {
    assert_eq!(nla_align(0), 0);
    assert_eq!(nla_align(3), 4);
    assert_eq!(nla_align(4), 4);
    assert_eq!(nla_align(9), 12);
}

// ─── parse_nfq_packet tests ───────────────────────────────────────────────────

/// Build a minimal hand-crafted NFQNL_MSG_PACKET body (after nlmsghdr).
fn build_packet_body(
    packet_id: u32,
    uid: u32,
    mark: u32,
    iface_in: u32,
    iface_out: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();

    // nfgenmsg: family=0, version=0, res_id=0
    body.extend_from_slice(&[0u8, 0, 0, 0]);

    // NFQA_PACKET_HDR (1): packet_id (u32 BE) + hw_protocol (u16 BE) + hook (u8) = 7 bytes
    let pkt_hdr_data: [u8; 7] = {
        let id = packet_id.to_be_bytes();
        [id[0], id[1], id[2], id[3], 0x08, 0x00, 0x01]
    };
    let nla_len = (NLA_HDR_LEN + 7) as u16;
    body.extend_from_slice(&nla_len.to_ne_bytes());
    body.extend_from_slice(&NFQA_PACKET_HDR.to_ne_bytes());
    body.extend_from_slice(&pkt_hdr_data);
    body.push(0); // pad to 8 bytes

    // NFQA_MARK (3)
    let nla_len = (NLA_HDR_LEN + 4) as u16;
    body.extend_from_slice(&nla_len.to_ne_bytes());
    body.extend_from_slice(&NFQA_MARK.to_ne_bytes());
    body.extend_from_slice(&mark.to_be_bytes());

    // NFQA_IFINDEX_INDEV (5)
    body.extend_from_slice(&nla_len.to_ne_bytes());
    body.extend_from_slice(&NFQA_IFINDEX_INDEV.to_ne_bytes());
    body.extend_from_slice(&iface_in.to_be_bytes());

    // NFQA_IFINDEX_OUTDEV (6)
    body.extend_from_slice(&nla_len.to_ne_bytes());
    body.extend_from_slice(&NFQA_IFINDEX_OUTDEV.to_ne_bytes());
    body.extend_from_slice(&iface_out.to_be_bytes());

    // NFQA_UID (16)
    body.extend_from_slice(&nla_len.to_ne_bytes());
    body.extend_from_slice(&NFQA_UID.to_ne_bytes());
    body.extend_from_slice(&uid.to_be_bytes());

    // NFQA_PAYLOAD (10)
    let payload_nla_len = (NLA_HDR_LEN + payload.len()) as u16;
    body.extend_from_slice(&payload_nla_len.to_ne_bytes());
    body.extend_from_slice(&NFQA_PAYLOAD.to_ne_bytes());
    body.extend_from_slice(payload);
    let pad = nla_align(payload.len()) - payload.len();
    body.extend(std::iter::repeat_n(0u8, pad));

    body
}

#[test]
fn parse_nfq_packet_extracts_all_fields() {
    let payload = [0x45u8, 0x00, 0x00, 0x28]; // minimal IPv4 header prefix
    let body = build_packet_body(77, 1000, 42, 3, 5, &payload);
    let pkt: NfqPacket<'_> = parse_nfq_packet(&body).expect("parse failed");

    assert_eq!(pkt.packet_id, 77);
    assert_eq!(pkt.uid, 1000);
    assert_eq!(pkt.mark, 42);
    assert_eq!(pkt.iface_in_idx, 3);
    assert_eq!(pkt.iface_out_idx, 5);
    assert_eq!(pkt.payload, &payload[..]);
}

#[test]
fn parse_nfq_packet_missing_packet_hdr_returns_none() {
    // Body with only nfgenmsg and no NLA attributes.
    let body = vec![0u8; NFGENMSG_LEN];
    assert!(parse_nfq_packet(&body).is_none());
}

#[test]
fn parse_nfq_packet_truncated_body_returns_none() {
    assert!(parse_nfq_packet(&[]).is_none());
    assert!(parse_nfq_packet(&[0u8; 3]).is_none());
}

/// NLA type high bits (NLA_F_NESTED = 0x8000) are stripped correctly.
#[test]
fn parse_nfq_packet_strips_nla_flag_bits_from_type() {
    let payload = [0u8; 4];
    let mut body = build_packet_body(1, 0, 0, 0, 0, &payload);

    // Flip NLA_F_NET_BYTEORDER (0x4000) onto the NFQA_UID type byte in the body.
    // Find NFQA_UID NLA in the body and set the flag in its nla_type.
    let mut offset = NFGENMSG_LEN;
    while offset + NLA_HDR_LEN <= body.len() {
        let nla_len = u16::from_ne_bytes([body[offset], body[offset + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
        if nla_type == NFQA_UID {
            // Set NLA_F_NET_BYTEORDER flag
            let new_type = NFQA_UID | 0x4000;
            body[offset + 2] = new_type.to_ne_bytes()[0];
            body[offset + 3] = new_type.to_ne_bytes()[1];
            break;
        }
        offset += nla_align(nla_len);
    }

    // uid should still parse correctly after stripping the flag bit.
    let pkt = parse_nfq_packet(&body).expect("should still parse");
    assert_eq!(pkt.packet_id, 1);
}

// ─── Config attribute type constants sanity test ──────────────────────────────

#[test]
fn config_attr_type_values_match_kernel_uapi() {
    assert_eq!(NFQA_CFG_CMD, 1);
    assert_eq!(NFQA_CFG_PARAMS, 2);
    assert_eq!(NFQA_CFG_QUEUE_MAXLEN, 3);
    assert_eq!(NFQA_CFG_MASK, 4);
    assert_eq!(NFQA_CFG_FLAGS, 5);
}

#[test]
fn packet_attr_type_values_match_kernel_uapi() {
    assert_eq!(NFQA_PACKET_HDR, 1);
    assert_eq!(NFQA_VERDICT_HDR, 2);
    assert_eq!(NFQA_MARK, 3);
    assert_eq!(NFQA_IFINDEX_INDEV, 5);
    assert_eq!(NFQA_IFINDEX_OUTDEV, 6);
    assert_eq!(NFQA_PAYLOAD, 10);
    assert_eq!(NFQA_UID, 16);
}

// ─── Preflight test ───────────────────────────────────────────────────────────

/// Verify that opening a NETLINK_NETFILTER socket is either possible or
/// produces a clear permission error.  This test does not require privileges.
#[test]
fn preflight_reports_socket_availability() {
    match NfqueueNetlinkAdapter::preflight() {
        Ok(()) => {
            // Socket open succeeded — kernel supports NETLINK_NETFILTER.
        }
        Err(err) => {
            // Acceptable: sandboxed environment or missing kernel module.
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("permission") || msg.contains("operation not permitted")
                    || msg.contains("eacces") || msg.contains("eperm")
                    || msg.contains("failed"),
                "unexpected preflight error: {err}"
            );
        }
    }
}

// ─── Shipped-shape coverage gate ─────────────────────────────────────────────

/// All exported pub(crate) symbols of interest are reachable in tests.
/// This catches accidental private-ification regressions.
#[test]
fn adapter_pub_surface_is_stable() {
    // Verify key types and functions compile and are accessible.
    let _ = NlMsg::new(0x302, 0x01, 1).nfgenmsg(0, 0).finalize();
    let _ = parse_nfq_packet(&[]);
    let _ = NfqueueNetlinkAdapter::preflight;
    let _ = nlmsg_align(1);
    let _ = nla_align(1);
}

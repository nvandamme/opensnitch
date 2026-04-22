use std::net::IpAddr;

use anyhow::Result;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, SOCK_DESTROY},
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags, Timer, nlas::Nla},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

use crate::models::socket_state::SocketInfo;

const TCP_ALL_STATES: u32 = (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12)
    | (0x2001);

trait SocketInfoDiagExt {
    fn diag_socket_id(&self) -> SocketId;
    fn cookie_bytes(&self) -> [u8; 8];
}

impl SocketInfoDiagExt for SocketInfo {
    fn diag_socket_id(&self) -> SocketId {
        SocketId {
            source_port: self.src_port,
            destination_port: self.dst_port,
            source_address: self.src,
            destination_address: self.dst,
            interface_id: self.iface,
            cookie: self.cookie_bytes(),
        }
    }

    fn cookie_bytes(&self) -> [u8; 8] {
        let mut cookie = [0_u8; 8];
        cookie[..4].copy_from_slice(&self.cookie0.to_ne_bytes());
        cookie[4..].copy_from_slice(&self.cookie1.to_ne_bytes());
        cookie
    }
}

trait SocketCookieExt {
    fn decode_words(self) -> (u32, u32);
}

impl SocketCookieExt for [u8; 8] {
    fn decode_words(self) -> (u32, u32) {
        (
            u32::from_ne_bytes([self[0], self[1], self[2], self[3]]),
            u32::from_ne_bytes([self[4], self[5], self[6], self[7]]),
        )
    }
}

pub fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
    let families: Vec<u8> = match family {
        0 => vec![AF_INET, AF_INET6],
        AF_INET | AF_INET6 => vec![family],
        _ => Vec::new(),
    };

    if families.is_empty() {
        return Ok(Vec::new());
    }

    let protocols: Vec<u8> = match protocol {
        0 => vec![IPPROTO_TCP, IPPROTO_UDP],
        _ => vec![protocol],
    };

    let mut out = Vec::new();
    for af in families {
        for proto in &protocols {
            out.extend(dump_sockets_family_proto(af, *proto)?);
        }
    }

    Ok(out)
}

fn dump_sockets_family_proto(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    let _ = socket.bind_auto()?.port_number();
    socket.connect(&SocketAddr::new(0, 0))?;

    let request = build_typed_request(family, protocol);
    let mut req_buf = vec![0; request.header.length as usize];
    request.serialize(&mut req_buf);
    socket.send(&req_buf, 0)?;

    let mut out = Vec::new();
    let mut recv_buf = vec![0_u8; 64 * 1024];

    while let Ok(size) = socket.recv(&mut &mut recv_buf[..], 0) {
        let mut offset = 0_usize;
        while offset < size {
            let bytes = &recv_buf[offset..size];
            let msg = match NetlinkMessage::<SockDiagMessage>::deserialize(bytes) {
                Ok(msg) => msg,
                Err(_) => break,
            };

            match msg.payload {
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                    out.push(SocketInfo::from(resp.as_ref()));
                }
                NetlinkPayload::Done(_) => return Ok(out),
                _ => {}
            }

            let len = msg.header.length as usize;
            if len == 0 {
                break;
            }
            offset += len;
        }
    }

    Ok(out)
}

pub fn find_socket(
    family: u8,
    protocol: u8,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
) -> Result<Option<SocketInfo>> {
    let sockets = dump_sockets(family, protocol)?;

    for s in &sockets {
        if s.src_port == src_port && s.dst_port == dst_port && s.src == src && s.dst == dst {
            return Ok(Some(s.clone()));
        }
    }

    // Go daemon fallback behavior: if destination is wildcard, keep as potential match.
    for s in &sockets {
        if s.src_port == src_port && s.src == src && s.dst_port == 0 && s.dst.is_unspecified() {
            return Ok(Some(s.clone()));
        }
    }

    Ok(None)
}

pub fn kill_socket(family: u8, protocol: u8, socket: &SocketInfo) -> Result<()> {
    let mut sock = Socket::new(libc::NETLINK_INET_DIAG as isize)?;
    let _ = sock.bind_auto()?.port_number();
    sock.connect(&SocketAddr::new(0, 0))?;
    let msg = build_destroy_message(family, protocol, socket);
    let mut req = vec![0_u8; msg.buffer_len()];
    msg.serialize(&mut req);
    sock.send(&req, 0)?;
    Ok(())
}

fn build_typed_request(family: u8, protocol: u8) -> NetlinkMessage<SockDiagMessage> {
    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let socket_id = if family == AF_INET6 {
        SocketId::new_v6()
    } else {
        SocketId::new_v4()
    };

    let mut msg = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::InetRequest(InetRequest {
            family,
            protocol,
            extensions: netlink_packet_sock_diag::inet::ExtensionFlags::all(),
            states: StateFlags::all(),
            socket_id,
        })
        .into(),
    );
    msg.finalize();
    msg
}

fn build_destroy_message(
    family: u8,
    protocol: u8,
    socket: &SocketInfo,
) -> NetlinkMessage<SockDiagMessage> {
    let socket_id = socket.diag_socket_id();

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK;
    header.sequence_number = 1;
    header.port_number = std::process::id();

    let mut msg = NetlinkMessage::new(
        header,
        SockDiagMessage::InetRequest(InetRequest {
            family,
            protocol,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::from_bits_truncate(TCP_ALL_STATES),
            socket_id,
        })
        .into(),
    );
    msg.finalize();
    msg.header.message_type = SOCK_DESTROY;
    msg
}

impl From<&netlink_packet_sock_diag::inet::InetResponse> for SocketInfo {
    fn from(response: &netlink_packet_sock_diag::inet::InetResponse) -> Self {
        let header = &response.header;
        let (timer, retrans, expires) = match &header.timer {
            Some(Timer::Retransmit(d, r)) => (1, *r, (d.as_millis() & 0xffff_ffff) as u32),
            Some(Timer::KeepAlive(d)) => (2, 0, (d.as_millis() & 0xffff_ffff) as u32),
            Some(Timer::TimeWait) => (3, 0, 0),
            Some(Timer::Probe(d)) => (4, 0, (d.as_millis() & 0xffff_ffff) as u32),
            None => (0, 0, 0),
        };

        let mut mark = 0_u32;
        for nla in &response.nlas {
            if let Nla::Mark(v) = nla {
                mark = *v;
                break;
            }
        }

        let (cookie0, cookie1) = header.socket_id.cookie.decode_words();

        Self {
            family: header.family,
            state: header.state,
            timer,
            retrans,
            src_port: header.socket_id.source_port,
            dst_port: header.socket_id.destination_port,
            src: header.socket_id.source_address,
            dst: header.socket_id.destination_address,
            expires,
            rqueue: header.recv_queue,
            wqueue: header.send_queue,
            uid: header.uid,
            inode: header.inode,
            iface: header.socket_id.interface_id,
            mark,
            cookie0,
            cookie1,
        }
    }
}

mod libc {
    pub use nix::libc::NETLINK_INET_DIAG;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_destroy_request_uses_sock_destroy_and_preserves_socket_identity() {
        let socket = SocketInfo {
            family: AF_INET,
            state: 0,
            timer: 0,
            retrans: 0,
            src_port: 4242,
            dst_port: 443,
            src: "10.1.1.2".parse().unwrap(),
            dst: "1.1.1.1".parse().unwrap(),
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

        let msg = build_destroy_message(AF_INET, IPPROTO_TCP, &socket);

        assert_eq!(msg.header.message_type, SOCK_DESTROY);
        assert_eq!(msg.header.flags & NLM_F_REQUEST, NLM_F_REQUEST);
        assert_eq!(msg.header.flags & NLM_F_ACK, NLM_F_ACK);

        let NetlinkPayload::InnerMessage(SockDiagMessage::InetRequest(ref req)) = msg.payload
        else {
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
            req.socket_id.cookie.decode_words(),
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
            src: "0.0.0.0".parse().unwrap(),
            dst: "0.0.0.0".parse().unwrap(),
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
            socket.cookie_bytes().decode_words(),
            (0x01020304, 0xa0b0c0d0)
        );
    }
}

use std::collections::HashSet;
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

pub(crate) struct SocketDiagAdapter;

impl SocketDiagAdapter {
    fn socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        let mut cookie = [0_u8; 8];
        cookie[..4].copy_from_slice(&socket.cookie0.to_ne_bytes());
        cookie[4..].copy_from_slice(&socket.cookie1.to_ne_bytes());
        cookie
    }

    fn diag_socket_id(socket: &SocketInfo) -> SocketId {
        SocketId {
            source_port: socket.src_port,
            destination_port: socket.dst_port,
            source_address: socket.src,
            destination_address: socket.dst,
            interface_id: socket.iface,
            cookie: Self::socket_cookie_bytes(socket),
        }
    }

    fn decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        (
            u32::from_ne_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]),
            u32::from_ne_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]),
        )
    }

    fn select_socket_candidates(
        sockets: &[SocketInfo],
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Vec<SocketInfo> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        for s in sockets {
            if s.src_port == src_port && s.dst_port == dst_port && s.src == src && s.dst == dst {
                if seen.insert((s.inode, s.uid, s.src_port, s.dst_port)) {
                    out.push(s.clone());
                }
            }
        }

        // Go parity fallback: include wildcard destination rows as potential matches.
        for s in sockets {
            if s.src_port == src_port && s.src == src && s.dst_port == 0 && s.dst.is_unspecified() {
                if seen.insert((s.inode, s.uid, s.src_port, s.dst_port)) {
                    out.push(s.clone());
                }
            }
        }

        // Go parity fallback: include same src/src-port/dst-port rows even when destination IP differs.
        for s in sockets {
            if s.src_port == src_port && s.src == src && s.dst_port == dst_port {
                if seen.insert((s.inode, s.uid, s.src_port, s.dst_port)) {
                    out.push(s.clone());
                }
            }
        }

        out
    }

    fn build_destroy_message(
        family: u8,
        protocol: u8,
        socket: &SocketInfo,
    ) -> NetlinkMessage<SockDiagMessage> {
        let socket_id = Self::diag_socket_id(socket);

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
                out.extend(Self::dump_sockets_family_proto(af, *proto)?);
            }
        }

        Ok(out)
    }

    fn dump_sockets_family_proto(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
        let _ = socket.bind_auto()?.port_number();
        socket.connect(&SocketAddr::new(0, 0))?;

        let request = Self::build_typed_request(family, protocol);
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
        let candidates =
            Self::find_socket_candidates(family, protocol, src, src_port, dst, dst_port)?;
        Ok(candidates.into_iter().next())
    }

    pub fn find_socket_candidates(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        let sockets = Self::dump_sockets(family, protocol)?;
        Ok(Self::select_socket_candidates(
            &sockets, src, src_port, dst, dst_port,
        ))
    }

    pub fn kill_socket(family: u8, protocol: u8, socket: &SocketInfo) -> Result<()> {
        let mut sock = Socket::new(libc::NETLINK_INET_DIAG as isize)?;
        let _ = sock.bind_auto()?.port_number();
        sock.connect(&SocketAddr::new(0, 0))?;
        let msg = Self::build_destroy_message(family, protocol, socket);
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        Self::socket_cookie_bytes(socket)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        Self::decode_cookie_words(cookie)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_select_socket_candidates(
        sockets: &[SocketInfo],
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Vec<SocketInfo> {
        Self::select_socket_candidates(sockets, src, src_port, dst, dst_port)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_build_destroy_message(
        family: u8,
        protocol: u8,
        socket: &SocketInfo,
    ) -> NetlinkMessage<SockDiagMessage> {
        Self::build_destroy_message(family, protocol, socket)
    }
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

        let (cookie0, cookie1) = SocketDiagAdapter::decode_cookie_words(header.socket_id.cookie);

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

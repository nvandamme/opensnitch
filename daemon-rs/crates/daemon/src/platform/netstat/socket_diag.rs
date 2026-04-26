use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use netlink_bindings::inet_diag::{self, BytecodeOp, BytecodeOpCode, Hostcond, ReqV2};
use netlink_bindings::traits::{NetlinkRequest, Protocol};
use netlink_socket2::NetlinkSocket;

use crate::models::socket_state::SocketInfo;
use crate::platform::netlink::io::{
    for_each_reply, netlink_map_io_error, netlink_map_reply_error, request_with_ack,
};

const SOCKET_DIAG_FAMILIES: [u8; 2] = [nix::libc::AF_INET as u8, nix::libc::AF_INET6 as u8];
const SOCKET_DIAG_PROTOCOLS: [u8; 2] = [nix::libc::IPPROTO_TCP as u8, nix::libc::IPPROTO_UDP as u8];

fn tcp_all_states_mask() -> u32 {
    let states = [
        inet_diag::TcpState::Established,
        inet_diag::TcpState::SynSent,
        inet_diag::TcpState::SynRecv,
        inet_diag::TcpState::FinWait1,
        inet_diag::TcpState::FinWait2,
        inet_diag::TcpState::TimeWait,
        inet_diag::TcpState::Close,
        inet_diag::TcpState::CloseWait,
        inet_diag::TcpState::LastAck,
        inet_diag::TcpState::Listen,
        inet_diag::TcpState::Closing,
        inet_diag::TcpState::NewSynRecv,
        inet_diag::TcpState::BoundInactive,
    ];
    states
        .into_iter()
        .fold(1_u32, |mask, state| mask | (1_u32 << (state as u32)))
}

struct KillSocketRequest {
    payload: ReqV2,
}

impl NetlinkRequest for KillSocketRequest {
    fn protocol(&self) -> Protocol {
        Protocol::Raw {
            protonum: inet_diag::PROTONUM,
            request_type: sock_destroy_request_type(),
        }
    }

    fn flags(&self) -> u16 {
        0
    }

    fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    type ReplyType<'buf> = &'buf [u8];

    fn decode_reply<'buf>(buf: &'buf [u8]) -> Self::ReplyType<'buf> {
        buf
    }
}

fn sock_destroy_request_type() -> u16 {
    let header = ReqV2::new();
    let request = inet_diag::Request::new().op_tcp_diag_dump(&header);
    match request.protocol() {
        Protocol::Raw { request_type, .. } => request_type + 1,
        Protocol::Generic(_) => unreachable!("inet_diag dump operation must use raw protocol"),
    }
}

pub(crate) struct SocketDiagAdapter;

impl SocketDiagAdapter {
    fn family_protocol_pairs(family: u8, protocol: u8) -> impl Iterator<Item = (u8, u8)> {
        SOCKET_DIAG_FAMILIES
            .into_iter()
            .filter(move |af| family == 0 || family == *af)
            .flat_map(move |af| {
                SOCKET_DIAG_PROTOCOLS
                    .into_iter()
                    .filter(move |proto| protocol == 0 || protocol == *proto)
                    .map(move |proto| (af, proto))
            })
    }

    fn select_socket_candidates(
        sockets: Vec<SocketInfo>,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Vec<SocketInfo> {
        let mut exact = Vec::new();
        let mut wildcard_dst = Vec::new();
        let mut relaxed_dst = Vec::new();
        let mut seen = HashSet::new();

        for socket in sockets {
            if socket.src_port != src_port || socket.src != src {
                continue;
            }

            let dedup_key = (socket.inode, socket.uid, socket.src_port, socket.dst_port);

            if socket.dst_port == dst_port && socket.dst == dst {
                if seen.insert(dedup_key) {
                    exact.push(socket);
                }
            } else if socket.dst_port == 0 && socket.dst.is_unspecified() {
                if seen.insert(dedup_key) {
                    wildcard_dst.push(socket);
                }
            } else if socket.dst_port == dst_port {
                if seen.insert(dedup_key) {
                    relaxed_dst.push(socket);
                }
            }
        }

        exact.extend(wildcard_dst);
        exact.extend(relaxed_dst);
        exact
    }

    #[cfg(test)]
    pub(crate) fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        crate::platform::netlink::runtime::run_on_netlink_rt(Self::dump_sockets_async(
            family, protocol,
        ))
    }

    pub(crate) async fn dump_sockets_async(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        let mut sock = crate::platform::netlink::io::new_request_socket();
        let mut out = Vec::new();
        for (af, proto) in Self::family_protocol_pairs(family, protocol) {
            out.extend(Self::dump_sockets_family_proto(&mut sock, af, proto).await?);
        }

        Ok(out)
    }

    async fn dump_sockets_family_proto(
        sock: &mut NetlinkSocket,
        family: u8,
        protocol: u8,
    ) -> Result<Vec<SocketInfo>> {
        let mut req = ReqV2::new();
        req.family = family;
        req.protocol = protocol;
        req.states = tcp_all_states_mask();

        Self::collect_sockets(sock, family, protocol, &req, None, None).await
    }

    pub(crate) fn find_socket(
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

    pub(crate) fn find_socket_candidates(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        crate::platform::netlink::runtime::run_on_netlink_rt(Self::find_socket_candidates_async(
            family, protocol, src, src_port, dst, dst_port,
        ))
    }

    pub(crate) async fn find_socket_candidates_async(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        let sockets = Self::find_socket_candidates_filtered_async(
            family, protocol, src, src_port, dst, dst_port,
        )
        .await?;
        Ok(Self::select_socket_candidates(
            sockets, src, src_port, dst, dst_port,
        ))
    }

    async fn find_socket_candidates_filtered_async(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        let mut sock = crate::platform::netlink::io::new_request_socket();
        let mut out = Vec::new();
        for (af, proto) in Self::family_protocol_pairs(family, protocol) {
            out.extend(
                Self::find_socket_candidates_family_proto(
                    &mut sock, af, proto, src, src_port, dst, dst_port,
                )
                .await?,
            );
        }

        Ok(out)
    }

    async fn find_socket_candidates_family_proto(
        sock: &mut NetlinkSocket,
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        let mut req = ReqV2::new();
        req.family = family;
        req.protocol = protocol;
        req.states = tcp_all_states_mask();
        req.ext = u8::MAX;
        req.sockid.set_sport(src_port);
        req.sockid.set_dport(dst_port);

        let bytecode = Self::build_hostcond_bytecode(family, src, src_port);

        Self::collect_sockets(
            sock,
            family,
            protocol,
            &req,
            Some(&bytecode),
            Some((dst, dst_port)),
        )
        .await
    }

    async fn collect_sockets(
        sock: &mut NetlinkSocket,
        family: u8,
        protocol: u8,
        req: &ReqV2,
        bytecode: Option<&[u8]>,
        dst_filter: Option<(IpAddr, u16)>,
    ) -> Result<Vec<SocketInfo>> {
        let mut out = Vec::new();

        match protocol {
            x if x == nix::libc::IPPROTO_TCP as u8 => {
                let mut request = inet_diag::Request::new().op_tcp_diag_dump(req);
                if let Some(bytecode) = bytecode {
                    request.encode().push_bytecode(bytecode);
                }
                for_each_reply(
                    sock,
                    &request,
                    netlink_map_io_error!(
                        "tcp_diag_dump request",
                        "socket-diag netlink io error",
                        family = family,
                        protocol = protocol
                    ),
                    netlink_map_reply_error!(
                        "tcp_diag_dump reply",
                        "socket-diag netlink reply error",
                        family = family,
                        protocol = protocol
                    ),
                    |(msg, attrs)| {
                        let socket = Self::to_socket_info(msg, attrs.get_mark().unwrap_or(0));
                        if let Some((dst, dst_port)) = dst_filter {
                            if socket.dst_port == dst_port && socket.dst == dst {
                                out.push(socket);
                            }
                        } else {
                            out.push(socket);
                        }
                        Ok(())
                    },
                )
                .await?;
            }
            x if x == nix::libc::IPPROTO_UDP as u8 => {
                let mut request = inet_diag::Request::new().op_udp_diag_dump(req);
                if let Some(bytecode) = bytecode {
                    request.encode().push_bytecode(bytecode);
                }
                for_each_reply(
                    sock,
                    &request,
                    netlink_map_io_error!(
                        "udp_diag_dump request",
                        "socket-diag netlink io error",
                        family = family,
                        protocol = protocol
                    ),
                    netlink_map_reply_error!(
                        "udp_diag_dump reply",
                        "socket-diag netlink reply error",
                        family = family,
                        protocol = protocol
                    ),
                    |(msg, attrs)| {
                        let socket = Self::to_socket_info(msg, attrs.get_mark().unwrap_or(0));
                        if let Some((dst, dst_port)) = dst_filter {
                            if socket.dst_port == dst_port && socket.dst == dst {
                                out.push(socket);
                            }
                        } else {
                            out.push(socket);
                        }
                        Ok(())
                    },
                )
                .await?;
            }
            _ => {}
        }

        Ok(out)
    }

    fn build_hostcond_bytecode(family: u8, src: IpAddr, src_port: u16) -> Vec<u8> {
        let mut bytecode = Vec::with_capacity(BytecodeOp::len() + Hostcond::len() + 16);

        let mut saddr_cond = BytecodeOp {
            code: BytecodeOpCode::SaddrCond as u8,
            yes: 0,
            no: 0,
        };

        let hc = Hostcond {
            family,
            prefix_len: match family {
                x if x == nix::libc::AF_INET as u8 => 32,
                x if x == nix::libc::AF_INET6 as u8 => 128,
                _ => 0,
            },
            port: src_port as i32,
            ..Default::default()
        };

        let start = bytecode.len();
        bytecode.extend(saddr_cond.as_slice());
        bytecode.extend(hc.as_slice());
        Self::encode_ip_compact(&mut bytecode, src);

        let len = bytecode.len();
        saddr_cond.yes = len as u8;
        saddr_cond.no = (len + BytecodeOp::len()) as u16;
        bytecode[start..(start + BytecodeOp::len())].clone_from_slice(saddr_cond.as_slice());

        bytecode
    }

    fn encode_ip_compact(buf: &mut Vec<u8>, val: IpAddr) {
        match val {
            IpAddr::V4(addr) => buf.extend(addr.octets()),
            IpAddr::V6(addr) => buf.extend(addr.octets()),
        }
    }

    fn to_socket_info(msg: inet_diag::Msg, mark: u32) -> SocketInfo {
        let (cookie0, cookie1) = Self::decode_cookie_words(msg.sockid.cookie);

        SocketInfo {
            family: msg.family,
            state: msg.state,
            timer: msg.timer,
            retrans: msg.retrans,
            src_port: msg.sockid.sport(),
            dst_port: msg.sockid.dport(),
            src: Self::decode_ip(msg.family, msg.sockid.src),
            dst: Self::decode_ip(msg.family, msg.sockid.dst),
            expires: msg.expires,
            rqueue: msg.rqueue,
            wqueue: msg.wqueue,
            uid: msg.uid,
            inode: msg.inode,
            iface: msg.sockid.r#if,
            mark,
            cookie0,
            cookie1,
        }
    }

    pub(crate) fn kill_socket(family: u8, protocol: u8, socket: &SocketInfo) -> Result<()> {
        let socket = socket.clone();
        crate::platform::netlink::runtime::run_on_netlink_rt(Self::kill_socket_async(
            family,
            protocol,
            socket,
        ))
    }

    pub(crate) async fn kill_socket_async(
        family: u8,
        protocol: u8,
        socket: SocketInfo,
    ) -> Result<()> {
        let req = Self::build_kill_req_v2(family, protocol, &socket);
        let request = KillSocketRequest { payload: req };

        let mut sock = crate::platform::netlink::io::new_request_socket();
        request_with_ack(
            &mut sock,
            &request,
            netlink_map_io_error!(
                "sock_destroy request",
                "socket-diag netlink io error",
                family = family,
                protocol = protocol
            ),
            netlink_map_reply_error!(
                "sock_destroy ack",
                "socket-diag netlink reply error",
                family = family,
                protocol = protocol
            ),
        )
        .await?;
        Ok(())
    }

    fn build_kill_req_v2(family: u8, protocol: u8, socket: &SocketInfo) -> ReqV2 {
        let mut req = ReqV2::new();
        req.family = family;
        req.protocol = protocol;
        req.states = tcp_all_states_mask();
        req.sockid.set_sport(socket.src_port);
        req.sockid.set_dport(socket.dst_port);
        req.sockid.src = Self::encode_ip(family, socket.src);
        req.sockid.dst = Self::encode_ip(family, socket.dst);
        req.sockid.r#if = socket.iface;
        req.sockid.cookie = Self::socket_cookie_bytes(socket);
        req
    }

    fn socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        let mut cookie = [0_u8; 8];
        cookie[..4].copy_from_slice(&socket.cookie0.to_ne_bytes());
        cookie[4..].copy_from_slice(&socket.cookie1.to_ne_bytes());
        cookie
    }

    fn encode_ip(family: u8, addr: IpAddr) -> [u8; 16] {
        match (family, addr) {
            (x, IpAddr::V4(v4)) if x == nix::libc::AF_INET as u8 => {
                let oct = v4.octets();
                [
                    oct[0], oct[1], oct[2], oct[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
            }
            (x, IpAddr::V6(v6)) if x == nix::libc::AF_INET6 as u8 => v6.octets(),
            (x, IpAddr::V6(_)) if x == nix::libc::AF_INET as u8 => [0_u8; 16],
            (x, IpAddr::V4(_)) if x == nix::libc::AF_INET6 as u8 => [0_u8; 16],
            _ => [0_u8; 16],
        }
    }

    fn decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        (
            u32::from_ne_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]),
            u32::from_ne_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]),
        )
    }

    fn decode_ip(family: u8, addr: [u8; 16]) -> IpAddr {
        match family {
            x if x == nix::libc::AF_INET as u8 => {
                IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
            }
            x if x == nix::libc::AF_INET6 as u8 => IpAddr::V6(Ipv6Addr::from(addr)),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_build_kill_req_v2(family: u8, protocol: u8, socket: &SocketInfo) -> ReqV2 {
        Self::build_kill_req_v2(family, protocol, socket)
    }

    #[cfg(test)]
    pub(crate) fn probe_socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        Self::socket_cookie_bytes(socket)
    }

    #[cfg(test)]
    pub(crate) fn probe_decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        Self::decode_cookie_words(cookie)
    }

    #[cfg(test)]
    pub(crate) fn probe_select_socket_candidates(
        sockets: &[SocketInfo],
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Vec<SocketInfo> {
        Self::select_socket_candidates(sockets.to_vec(), src, src_port, dst, dst_port)
    }
}

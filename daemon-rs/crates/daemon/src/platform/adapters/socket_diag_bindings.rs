use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use netlink_bindings::inet_diag::{self, BytecodeOp, BytecodeOpCode, Hostcond, ReqV2};
use netlink_bindings::traits::{NetlinkRequest, Protocol};
use netlink_socket2::{NetlinkSocket, ReplyError};

use crate::models::socket_state::SocketInfo;

const AF_INET: u8 = nix::libc::AF_INET as u8;
const AF_INET6: u8 = nix::libc::AF_INET6 as u8;
const IPPROTO_TCP: u8 = nix::libc::IPPROTO_TCP as u8;
const IPPROTO_UDP: u8 = nix::libc::IPPROTO_UDP as u8;
const SOCK_DESTROY: u16 = 21;

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

pub(crate) struct SocketDiagBindingsAdapter;

struct KillSocketRequest {
    payload: Vec<u8>,
}

impl NetlinkRequest for KillSocketRequest {
    fn protocol(&self) -> Protocol {
        Protocol::Raw {
            protonum: inet_diag::PROTONUM,
            request_type: SOCK_DESTROY,
        }
    }

    fn flags(&self) -> u16 {
        0
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    type ReplyType<'buf> = &'buf [u8];

    fn decode_reply<'buf>(buf: &'buf [u8]) -> Self::ReplyType<'buf> {
        buf
    }
}

impl SocketDiagBindingsAdapter {
    #[allow(dead_code)]
    pub(crate) fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        super::netlink_rt::run_on_netlink_rt(Self::dump_sockets_async(family, protocol))
    }

    pub(crate) async fn dump_sockets_async(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
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

        let mut sock = NetlinkSocket::new();
        let mut out = Vec::new();
        for af in families {
            for proto in &protocols {
                out.extend(Self::dump_sockets_family_proto(&mut sock, af, *proto).await?);
            }
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
        req.states = TCP_ALL_STATES;

        Self::collect_sockets(sock, family, protocol, &req, None, None).await
    }

    pub(crate) fn find_socket_candidates_filtered(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        super::netlink_rt::run_on_netlink_rt(Self::find_socket_candidates_filtered_async(
            family, protocol, src, src_port, dst, dst_port,
        ))
    }

    pub(crate) async fn find_socket_candidates_filtered_async(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
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

        let mut sock = NetlinkSocket::new();
        let mut out = Vec::new();
        for af in families {
            for proto in &protocols {
                out.extend(
                    Self::find_socket_candidates_family_proto(
                        &mut sock, af, *proto, src, src_port, dst, dst_port,
                    )
                    .await?,
                );
            }
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
        req.states = TCP_ALL_STATES;
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
            IPPROTO_TCP => {
                let mut request = inet_diag::Request::new().op_tcp_diag_dump(req);
                if let Some(bytecode) = bytecode {
                    request.encode().push_bytecode(bytecode);
                }

                let mut iter = sock.request(&request).await.map_err(|err| {
                    Self::map_io_error("tcp_diag_dump request", family, protocol, err)
                })?;

                while let Some(reply) = iter.recv().await {
                    let (msg, attrs) = reply.map_err(|err| {
                        Self::map_reply_error("tcp_diag_dump reply", family, protocol, err)
                    })?;
                    let socket = Self::to_socket_info(msg, attrs.get_mark().unwrap_or(0));

                    if let Some((dst, dst_port)) = dst_filter {
                        if socket.dst_port == dst_port && socket.dst == dst {
                            out.push(socket);
                        }
                    } else {
                        out.push(socket);
                    }
                }
            }
            IPPROTO_UDP => {
                let mut request = inet_diag::Request::new().op_udp_diag_dump(req);
                if let Some(bytecode) = bytecode {
                    request.encode().push_bytecode(bytecode);
                }

                let mut iter = sock.request(&request).await.map_err(|err| {
                    Self::map_io_error("udp_diag_dump request", family, protocol, err)
                })?;

                while let Some(reply) = iter.recv().await {
                    let (msg, attrs) = reply.map_err(|err| {
                        Self::map_reply_error("udp_diag_dump reply", family, protocol, err)
                    })?;
                    let socket = Self::to_socket_info(msg, attrs.get_mark().unwrap_or(0));

                    if let Some((dst, dst_port)) = dst_filter {
                        if socket.dst_port == dst_port && socket.dst == dst {
                            out.push(socket);
                        }
                    } else {
                        out.push(socket);
                    }
                }
            }
            _ => {}
        }

        Ok(out)
    }

    fn map_io_error(
        action: &'static str,
        family: u8,
        protocol: u8,
        err: std::io::Error,
    ) -> anyhow::Error {
        tracing::warn!(
            action,
            family,
            protocol,
            detail = %err,
            "socket-diag netlink io error"
        );
        anyhow::Error::new(err)
    }

    fn map_reply_error(
        action: &'static str,
        family: u8,
        protocol: u8,
        err: ReplyError,
    ) -> anyhow::Error {
        Self::log_reply_error(action, family, protocol, &err);
        anyhow::Error::new(err)
    }

    fn log_reply_error(action: &'static str, family: u8, protocol: u8, err: &ReplyError) {
        let errno = err.as_io_error().raw_os_error().unwrap_or_default();
        let extack_message = err
            .ext_ack()
            .and_then(|attrs| attrs.get_msg().ok())
            .map(|msg| msg.to_string_lossy().into_owned())
            .unwrap_or_else(|| "-".to_string());

        tracing::warn!(
            action,
            family,
            protocol,
            errno,
            extack = %extack_message,
            detail = %err,
            "socket-diag netlink reply error"
        );
    }

    fn build_hostcond_bytecode(family: u8, src: IpAddr, src_port: u16) -> Vec<u8> {
        let mut bytecode = Vec::new();

        let mut saddr_cond = BytecodeOp {
            code: BytecodeOpCode::SaddrCond as u8,
            yes: 0,
            no: 0,
        };

        let hc = Hostcond {
            family,
            prefix_len: match family {
                AF_INET => 32,
                AF_INET6 => 128,
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
        super::netlink_rt::run_on_netlink_rt(Self::kill_socket_async(
            family,
            protocol,
            socket.clone(),
        ))
    }

    pub(crate) async fn kill_socket_async(
        family: u8,
        protocol: u8,
        socket: SocketInfo,
    ) -> Result<()> {
        let req = Self::build_kill_req_v2(family, protocol, &socket);
        let request = KillSocketRequest {
            payload: req.as_slice().to_vec(),
        };

        let mut sock = NetlinkSocket::new();
        let mut reply = sock
            .request(&request)
            .await
            .map_err(|err| Self::map_io_error("sock_destroy request", family, protocol, err))?;
        reply
            .recv_ack()
            .await
            .map_err(|err| Self::map_reply_error("sock_destroy ack", family, protocol, err))?;
        Ok(())
    }

    fn build_kill_req_v2(family: u8, protocol: u8, socket: &SocketInfo) -> ReqV2 {
        let mut req = ReqV2::new();
        req.family = family;
        req.protocol = protocol;
        req.states = TCP_ALL_STATES;
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
            (AF_INET, IpAddr::V4(v4)) => {
                let oct = v4.octets();
                [
                    oct[0], oct[1], oct[2], oct[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
            }
            (AF_INET6, IpAddr::V6(v6)) => v6.octets(),
            (AF_INET, IpAddr::V6(_)) => [0_u8; 16],
            (AF_INET6, IpAddr::V4(_)) => [0_u8; 16],
            _ => [0_u8; 16],
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_build_kill_req_v2(family: u8, protocol: u8, socket: &SocketInfo) -> ReqV2 {
        Self::build_kill_req_v2(family, protocol, socket)
    }

    fn decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        (
            u32::from_ne_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]),
            u32::from_ne_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]),
        )
    }

    fn decode_ip(family: u8, addr: [u8; 16]) -> IpAddr {
        match family {
            AF_INET => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(addr)),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

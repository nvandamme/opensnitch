use std::net::IpAddr;

use anyhow::Result;

use crate::{models::socket_state::SocketInfo, platform::adapters::socket_diag::SocketDiagAdapter};

pub(crate) trait SocketDiagPlatformPort {
    fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>>;

    fn find_socket_candidates(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>>;
}

pub(crate) struct NativeSocketDiagPort;

impl SocketDiagPlatformPort for NativeSocketDiagPort {
    fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        SocketDiagAdapter::dump_sockets(family, protocol)
    }

    fn find_socket_candidates(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        SocketDiagAdapter::find_socket_candidates(family, protocol, src, src_port, dst, dst_port)
    }
}

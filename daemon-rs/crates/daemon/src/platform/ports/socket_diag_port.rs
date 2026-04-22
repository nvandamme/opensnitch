use std::net::IpAddr;

use anyhow::Result;

use crate::{models::socket_state::SocketInfo, platform::adapters::socket_diag::SocketDiagAdapter};

pub(crate) trait SocketDiagPlatformPort {
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

impl NativeSocketDiagPort {
    pub(crate) async fn dump_sockets_async(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        SocketDiagAdapter::dump_sockets_async(family, protocol).await
    }
    // Optional async helper retained for profiles that perform socket ownership checks.
    #[allow(dead_code)]
    pub(crate) async fn find_socket_candidates_async(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        SocketDiagAdapter::find_socket_candidates_async(
            family, protocol, src, src_port, dst, dst_port,
        )
        .await
    }
}

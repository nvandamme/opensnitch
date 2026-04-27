use std::net::IpAddr;

use super::state::TransportProtocol;

#[derive(Debug, Clone, Copy)]
pub struct ConnectionOwner {
    pub uid: u32,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionOwnerCacheKey {
    pub protocol: TransportProtocol,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

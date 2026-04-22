use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    UdpLite,
    Sctp,
    Icmp,
}

#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    pub request_id: u64,
    pub protocol: TransportProtocol,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub iface_in_idx: u32,
    pub iface_out_idx: u32,
    pub dns_query: Option<String>,
    pub pid: u32,
    pub uid: u32,
}

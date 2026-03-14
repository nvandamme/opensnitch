#[derive(Debug, Clone, Copy)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    pub request_id: u64,
    pub protocol: TransportProtocol,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub family: u8,
    pub state: u8,
    pub timer: u8,
    pub retrans: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub expires: u32,
    pub rqueue: u32,
    pub wqueue: u32,
    pub uid: u32,
    pub inode: u32,
    pub iface: u32,
    pub mark: u32,
    pub cookie0: u32,
    pub cookie1: u32,
}

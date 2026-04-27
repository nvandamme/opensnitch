#[derive(Debug, Clone, Copy)]
pub struct ProcNetPacketRow {
    pub iface: u32,
    pub uid: u32,
    pub inode: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcNetXdpRow {
    pub iface: u32,
    pub uid: u32,
    pub inode: u32,
    pub cookie0: u32,
    pub cookie1: u32,
}

use netlink_sys::Socket;

#[derive(Debug, Clone, Copy)]
pub enum ProcEventKind {
    Fork,
    Exec,
    Exit,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcPidEvent {
    pub pid: u32,
    pub kind: ProcEventKind,
}

pub struct ProcEventSocket {
    pub(crate) sock: Socket,
}

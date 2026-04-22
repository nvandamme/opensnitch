#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

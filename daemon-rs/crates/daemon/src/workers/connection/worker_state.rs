#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionWorkerKind {
    Ebpf,
    Fallback,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionWorkerState {
    pub worker_kind: ConnectionWorkerKind,
}

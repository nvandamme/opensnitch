#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsWorkerKind {
    Ebpf,
    Fallback,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DnsWorkerState {
    pub worker_kind: DnsWorkerKind,
}

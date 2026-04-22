use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsExplicitRuntimeKind {
    #[cfg(feature = "aya-ebpf")]
    Aya,
    Libbpf,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DnsExplicitRuntime<'a> {
    pub(super) kind: DnsExplicitRuntimeKind,
    pub(super) obj: &'a Path,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DnsUprobeSpec {
    pub(super) program_name: &'static str,
    pub(super) section_name: &'static str,
    pub(super) symbol_name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcExplicitRuntimeKind {
    #[cfg(feature = "aya-ebpf")]
    Aya,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProcExplicitRuntime<'a> {
    pub(super) kind: ProcExplicitRuntimeKind,
    pub(super) obj: &'a Path,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ProcTracepointSpec {
    pub(super) program_name: &'static str,
    pub(super) section_name: &'static str,
    pub(super) category: &'static str,
    pub(super) name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnExplicitRuntimeKind {
    #[cfg(feature = "aya-ebpf")]
    Aya,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ConnExplicitRuntime<'a> {
    pub(super) kind: ConnExplicitRuntimeKind,
    pub(super) obj: &'a Path,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ConnKprobeSpec {
    pub(super) program_name: &'static str,
    pub(super) section_name: &'static str,
    pub(super) symbol_name: &'static str,
}

pub(super) const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const CONN_SUPERVISE_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const EBPFRING_ACTIVE_LOOP_INTERVAL: Duration = Duration::from_millis(50);

pub(super) struct EbpfWorkerRuntime {
    pub(super) shutdown: CancellationToken,
    pub(super) handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EbpfWorkerMode {
    pub(super) enable_dns: bool,
    pub(super) enable_proc: bool,
    pub(super) enable_conn: bool,
}

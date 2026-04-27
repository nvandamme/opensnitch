use crate::platform::procmon::ebpf_payload::EbpfProcStatePayload;
use crate::platform::procmon::proc_event::ProcEventKind;

#[derive(Debug)]
pub(crate) enum ProcessKernelEvent {
    ProcStateChanged { pid: u32, kind: ProcEventKind },
    EbpfProcStateChanged(EbpfProcStatePayload),
    EbpfProcessMapHit { pid: u32, uid: u32, note: String },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KernelPipeline {
    Dns,
    Process,
    Firewall,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KernelPipelineDropStats {
    pub dns: u64,
    pub process: u64,
    pub firewall: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KernelPipelineIngressStats {
    pub dns: u64,
    pub process: u64,
    pub firewall: u64,
}

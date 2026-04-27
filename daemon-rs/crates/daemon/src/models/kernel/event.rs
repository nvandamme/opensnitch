use crate::models::dns::payload::DnsPayload;
use crate::platform::firewall::state::FirewallState;
use crate::platform::procmon::ebpf_payload::EbpfProcStatePayload;
pub use crate::platform::procmon::proc_event::ProcEventKind;

#[derive(Debug, Clone)]
pub enum KernelEvent {
    EbpfProcessMapHit {
        pid: u32,
        uid: u32,
        note: String,
    },
    DnsUpdate(DnsPayload),
    ProcStateChanged {
        pid: u32,
        kind: ProcEventKind,
    },
    // Emitted only when native eBPF process-state wiring is active.
    #[cfg(feature = "native-ebpf-ringbuf")]
    EbpfProcStateChanged(EbpfProcStatePayload),
    FirewallState(FirewallState),
}

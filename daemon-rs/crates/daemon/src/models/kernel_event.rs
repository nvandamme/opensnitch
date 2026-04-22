use crate::models::dns_payload::DnsPayload;
use crate::models::ebpf_payload::EbpfProcStatePayload;
use crate::models::firewall_state::FirewallState;
pub use crate::models::proc_event::ProcEventKind;

#[derive(Debug, Clone)]
pub enum KernelEvent {
    EbpfProcessMapHit { pid: u32, uid: u32, note: String },
    DnsUpdate(DnsPayload),
    ProcStateChanged { pid: u32, kind: ProcEventKind },
    EbpfProcStateChanged(EbpfProcStatePayload),
    FirewallState(FirewallState),
}

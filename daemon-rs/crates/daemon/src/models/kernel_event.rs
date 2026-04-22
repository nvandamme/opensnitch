use crate::models::firewall_state::FirewallState;

#[derive(Debug, Clone, Copy)]
pub enum ProcEventKind {
    Fork,
    Exec,
    Exit,
}

#[derive(Debug, Clone)]
pub enum KernelEvent {
    EbpfProcessMapHit { pid: u32, uid: u32, note: String },
    DnsResolved { ip: String, host: String },
    ProcStateChanged { pid: u32, kind: ProcEventKind },
    FirewallState(FirewallState),
}

use crate::models::{connection::ConnectionAttempt, firewall::FirewallState};

#[derive(Debug, Clone)]
pub enum KernelEvent {
    ConnectAttempt(ConnectionAttempt),
    EbpfProcessMapHit { pid: u32, uid: u32, note: String },
    DnsResolved { ip: String, host: String },
    ProcStateChanged { pid: u32 },
    FirewallState(FirewallState),
}

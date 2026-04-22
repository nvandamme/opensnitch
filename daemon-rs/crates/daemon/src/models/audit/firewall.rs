/// Firewall service lifecycle transitions (including drift-heal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum FirewallLifecycle {
    Initialized,
    Started,
    Stopped,
    ReloadStarted,
    ReloadCompleted,
    ReloadFailed { reason: &'static str },
    HealStarted,
    HealCompleted,
    HealFailed { reason: &'static str },
    WorkerStarted,
}

/// Firewall service runtime actions (rule and chain management).
/// `handle` is a nftables handle or iptables rule spec summary.
#[derive(Debug, Clone)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum FirewallAction {
    EnsureRulesApplied,
    EnsureRulesSkipped,
    RuleAdded {
        chain: Box<str>,
        handle: Box<str>,
    },
    RuleDeleted {
        chain: Box<str>,
        handle: Box<str>,
    },
    RuleAddFailed {
        chain: Box<str>,
        reason: Box<str>,
    },
    RuleDeleteFailed {
        chain: Box<str>,
        reason: Box<str>,
    },
    ChainAdded {
        chain: Box<str>,
    },
    ChainDeleted {
        chain: Box<str>,
    },
    ChainFlushFailed {
        chain: Box<str>,
        reason: Box<str>,
    },
    /// A command-level firewall operation failed (set_enabled, reload_firewall, etc.).
    CommandFailed {
        reason: Box<str>,
    },
}

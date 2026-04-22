// The audit model defines the complete event vocabulary for the daemon.
// Many lifecycle variants and action variants are forward-defined and will
// gain emit sites as instrumentation coverage grows.
pub mod client;
pub mod config;
pub mod connection;
pub mod dns;
pub mod event;
pub mod family;
pub mod firewall;
pub mod kernel;
pub mod kind;
pub mod process;
pub mod rule;
pub mod severity;
pub mod stats;
pub mod storage;
pub mod subscription;
pub mod task;
pub mod verdict;

// ── Audit service ──────────────────────────────────────────────────────────
pub use event::{AuditEvent, AuditLifecycle};
pub use family::AuditEventFamily;
pub use kind::AuditEventKind;
pub use severity::AuditSeverity;

// ── Client ─────────────────────────────────────────────────────────────────
pub use client::{
    ClientAuthorizationAction, ClientLifecycle, CommandFlowLifecycle, NotificationFlowLifecycle,
};

// ── Config ─────────────────────────────────────────────────────────────────
pub use config::{ConfigAction, ConfigLifecycle};

// ── Connection ─────────────────────────────────────────────────────────────
pub use connection::{
    ConnectFlowAction, ConnectFlowLifecycle, ConnectionLifecycle, VerdictFlowLifecycle,
};

// ── DNS ────────────────────────────────────────────────────────────────────
pub use dns::{DnsAction, DnsLifecycle};

// ── Firewall ───────────────────────────────────────────────────────────────
pub use firewall::{FirewallAction, FirewallLifecycle};

// ── Kernel ─────────────────────────────────────────────────────────────────
pub use kernel::{KernelAction, KernelFlowAction, KernelFlowLifecycle};

// ── Process ────────────────────────────────────────────────────────────────
pub use process::{ProcessAction, ProcessLifecycle};

// ── Rule ───────────────────────────────────────────────────────────────────
pub use rule::{RuleAction, RuleLifecycle};

// ── Stats ──────────────────────────────────────────────────────────────────
pub use stats::{StatsFlowAction, StatsFlowLifecycle, StatsLifecycle};

// ── Storage ────────────────────────────────────────────────────────────────
pub use storage::{StorageAction, StorageLifecycle};

// ── Subscription ───────────────────────────────────────────────────────────
pub use subscription::{SubscriptionAction, SubscriptionFlowLifecycle, SubscriptionLifecycle};

// ── Task ───────────────────────────────────────────────────────────────────
pub use task::{ServiceObserverLifecycle, TaskAction, TaskLifecycle};

// ── Verdict ────────────────────────────────────────────────────────────────
pub use verdict::{VerdictAction, VerdictSource};

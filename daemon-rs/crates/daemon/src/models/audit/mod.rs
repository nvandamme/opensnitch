// The audit model defines the complete event vocabulary for the daemon.
// Many lifecycle variants and action variants are forward-defined and will
// gain emit sites as instrumentation coverage grows.
#[allow(dead_code)]
pub mod client;
#[allow(dead_code)]
pub mod config;
#[allow(dead_code)]
pub mod connection;
#[allow(dead_code)]
pub mod dns;
#[allow(dead_code)]
pub mod event;
#[allow(dead_code)]
pub mod family;
#[allow(dead_code)]
pub mod firewall;
#[allow(dead_code)]
pub mod kernel;
#[allow(dead_code)]
pub mod kind;
#[allow(dead_code)]
pub mod process;
#[allow(dead_code)]
pub mod rule;
#[allow(dead_code)]
pub mod severity;
#[allow(dead_code)]
pub mod stats;
#[allow(dead_code)]
pub mod storage;
#[allow(dead_code)]
pub mod subscription;
#[allow(dead_code)]
pub mod task;
#[allow(dead_code)]
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

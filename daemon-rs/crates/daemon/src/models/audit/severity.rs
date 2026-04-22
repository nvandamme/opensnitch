use super::AuditEventKind;

/// Security/operational severity classification for audit events.
///
/// Orthogonal to [`super::AuditEventFamily`] (which tags hot vs cold path):
/// severity drives syslog level selection and alert routing.
///
/// - [`Error`][AuditSeverity::Error]:   hard failures — sub-systems that may have stopped functioning.
/// - [`Warning`][AuditSeverity::Warning]: recoverable failures, auth denials, and security-notable conditions.
/// - [`Info`][AuditSeverity::Info]:    normal operational events (lifecycle transitions, successful actions).
/// - [`Debug`][AuditSeverity::Debug]:   verbose internal events, only surfaced when the subscriber log level is `debug` or finer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum AuditSeverity {
    Error,
    Warning,
    Info,
    Debug,
}

impl AuditSeverity {
    /// Derive severity from event kind.
    ///
    /// Emit sites use [`super::AuditEvent`] constructors — severity is computed
    /// automatically, not chosen by the call site.
    pub fn from_kind(kind: &AuditEventKind) -> Self {
        use super::{
            ClientAuthorizationAction, ClientLifecycle, CommandFlowLifecycle, ConfigLifecycle,
            ConnectFlowAction, ConnectFlowLifecycle, ConnectionLifecycle, DnsAction, DnsLifecycle,
            FirewallAction, FirewallLifecycle, KernelAction, KernelFlowAction, KernelFlowLifecycle,
            NotificationFlowLifecycle, ProcessAction, RuleAction, RuleLifecycle,
            ServiceObserverLifecycle, StatsFlowLifecycle, StatsLifecycle, StorageAction,
            StorageLifecycle, SubscriptionAction, SubscriptionFlowLifecycle, SubscriptionLifecycle,
            TaskAction, TaskLifecycle, VerdictFlowLifecycle,
        };

        match kind {
            // ── Hard failures (service-level, may indicate daemon malfunction) ──
            AuditEventKind::ConnectionLifecycle(ConnectionLifecycle::Failed { .. })
            | AuditEventKind::ConnectFlowLifecycle(ConnectFlowLifecycle::Failed { .. })
            | AuditEventKind::VerdictFlowLifecycle(VerdictFlowLifecycle::Failed { .. })
            | AuditEventKind::KernelFlowLifecycle(KernelFlowLifecycle::Failed { .. })
            | AuditEventKind::StatsFlowLifecycle(StatsFlowLifecycle::Failed { .. })
            | AuditEventKind::StatsLifecycle(StatsLifecycle::Failed { .. })
            | AuditEventKind::DnsLifecycle(DnsLifecycle::Failed { .. })
            | AuditEventKind::FirewallLifecycle(
                FirewallLifecycle::HealFailed { .. } | FirewallLifecycle::ReloadFailed { .. },
            )
            | AuditEventKind::StorageLifecycle(StorageLifecycle::Failed { .. })
            | AuditEventKind::TaskLifecycle(TaskLifecycle::ReloadFailed { .. })
            | AuditEventKind::TaskAction(TaskAction::TaskPanicked { .. })
            | AuditEventKind::ServiceObserverLifecycle(
                ServiceObserverLifecycle::ServiceObserverFailed { .. },
            ) => Self::Error,

            // ── Auth denials and recoverable failures (warning) ───────────
            AuditEventKind::ClientAuthorizationAction(
                ClientAuthorizationAction::DeniedOwnerScopeRules { .. }
                | ClientAuthorizationAction::DeniedOwnerScopeFirewall { .. }
                | ClientAuthorizationAction::DeniedAuthorizationPolicy { .. },
            )
            | AuditEventKind::ConfigAction(super::ConfigAction::UpdateFailed { .. })
            | AuditEventKind::RuleAction(
                RuleAction::RuleCommandFailed { .. }
                | RuleAction::RuleAddFailed { .. }
                | RuleAction::RuleUpdateFailed { .. }
                | RuleAction::RuleDeleteFailed { .. },
            )
            | AuditEventKind::RuleLifecycle(RuleLifecycle::ReloadFailed { .. })
            | AuditEventKind::FirewallAction(
                FirewallAction::RuleAddFailed { .. }
                | FirewallAction::RuleDeleteFailed { .. }
                | FirewallAction::ChainFlushFailed { .. }
                | FirewallAction::CommandFailed { .. },
            )
            | AuditEventKind::DnsAction(DnsAction::ResolutionFailed { .. })
            | AuditEventKind::StorageAction(
                StorageAction::FileReadFailed { .. } | StorageAction::FileWriteFailed { .. },
            )
            | AuditEventKind::StorageLifecycle(StorageLifecycle::StorageObserverLagged {
                ..
            })
            | AuditEventKind::SubscriptionAction(SubscriptionAction::RefreshFailed { .. })
            | AuditEventKind::SubscriptionLifecycle(SubscriptionLifecycle::ReloadFailed {
                ..
            })
            | AuditEventKind::SubscriptionFlowLifecycle(
                SubscriptionFlowLifecycle::StreamFailed { .. }
                | SubscriptionFlowLifecycle::CommandStreamFailed { .. },
            )
            | AuditEventKind::ClientLifecycle(ClientLifecycle::ReloadFailed { .. })
            | AuditEventKind::NotificationFlowLifecycle(NotificationFlowLifecycle::Failed)
            | AuditEventKind::CommandFlowLifecycle(CommandFlowLifecycle::Failed { .. })
            | AuditEventKind::ConfigLifecycle(ConfigLifecycle::ReloadFailed { .. })
            | AuditEventKind::KernelAction(KernelAction::KernelPipelineDropsObserved { .. })
            | AuditEventKind::KernelFlowAction(
                KernelFlowAction::QueueOverflow { .. } | KernelFlowAction::PacketDropped,
            )
            | AuditEventKind::ConnectFlowAction(ConnectFlowAction::ConnectionDropped)
            | AuditEventKind::TaskAction(
                TaskAction::TaskRuntimePauseFailed
                | TaskAction::TaskRuntimeResumeFailed
                | TaskAction::TaskRuntimeStopFailed,
            ) => Self::Warning,

            // ── Verbose per-connection/per-packet events (debug) ──────────
            // Emitted only when verbose hot-path audit is explicitly enabled.
            AuditEventKind::ConnectFlowAction(ConnectFlowAction::ConnectionTracked)
            | AuditEventKind::DnsAction(
                DnsAction::CacheUpdated { .. }
                | DnsAction::CacheEvicted { .. }
                | DnsAction::ResolutionReceived { .. },
            )
            | AuditEventKind::ProcessAction(
                ProcessAction::ProcessTracked { .. }
                | ProcessAction::ProcessEvicted { .. }
                | ProcessAction::ProcessScanFailed { .. },
            )
            | AuditEventKind::KernelAction(KernelAction::KernelInterfaceReattached { .. })
            | AuditEventKind::StorageAction(
                StorageAction::FileRead { .. } | StorageAction::FileWritten { .. },
            ) => Self::Debug,

            // ── Normal operational events (info) ──────────────────────────
            _ => Self::Info,
        }
    }
}

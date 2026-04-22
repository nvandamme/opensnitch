use super::{
    // Audit
    AuditLifecycle,
    // Client (service + flows + auth)
    ClientAuthorizationAction,
    ClientLifecycle,
    CommandFlowLifecycle,
    // Config
    ConfigAction,
    ConfigLifecycle,
    // Connection (service + flows)
    ConnectFlowAction,
    ConnectFlowLifecycle,
    ConnectionLifecycle,
    // DNS
    DnsAction,
    DnsLifecycle,
    // Firewall
    FirewallAction,
    FirewallLifecycle,
    // Kernel (pipeline observations + kernel flow)
    KernelAction,
    KernelFlowAction,
    KernelFlowLifecycle,
    NotificationFlowLifecycle,
    // Process
    ProcessAction,
    ProcessLifecycle,
    // Rule
    RuleAction,
    RuleLifecycle,
    // Task (service + observer flow)
    ServiceObserverLifecycle,
    // Stats (service + flow)
    StatsFlowAction,
    StatsFlowLifecycle,
    StatsLifecycle,
    // Storage
    StorageAction,
    StorageLifecycle,
    // Subscription (service + flow)
    SubscriptionAction,
    SubscriptionFlowLifecycle,
    SubscriptionLifecycle,
    TaskAction,
    TaskLifecycle,
    // Verdict
    VerdictAction,
    VerdictFlowLifecycle,
};

/// All auditable event kinds, grouped by convention axis:
///
/// - `*Lifecycle` variants carry service/flow lifecycle events (init, start, stop, reload, fail).
/// - `*Action`    variants carry domain runtime behavior events (CRUD, I/O, cache, pressure, decisions).
#[derive(Debug, Clone)]
pub enum AuditEventKind {
    // ── Service lifecycles ─────────────────────────────────────────────────
    AuditLifecycle(AuditLifecycle),
    ClientLifecycle(ClientLifecycle),
    ConfigLifecycle(ConfigLifecycle),
    ConnectionLifecycle(ConnectionLifecycle),
    DnsLifecycle(DnsLifecycle),
    FirewallLifecycle(FirewallLifecycle),
    ProcessLifecycle(ProcessLifecycle),
    RuleLifecycle(RuleLifecycle),
    StatsLifecycle(StatsLifecycle),
    StorageLifecycle(StorageLifecycle),
    SubscriptionLifecycle(SubscriptionLifecycle),
    TaskLifecycle(TaskLifecycle),

    // ── Service actions ────────────────────────────────────────────────────
    ClientAuthorizationAction(ClientAuthorizationAction),
    ConfigAction(ConfigAction),
    DnsAction(DnsAction),
    FirewallAction(FirewallAction),
    KernelAction(KernelAction),
    ProcessAction(ProcessAction),
    RuleAction(RuleAction),
    StorageAction(StorageAction),
    SubscriptionAction(SubscriptionAction),
    TaskAction(TaskAction),
    VerdictAction(VerdictAction),

    // ── Flow lifecycles ────────────────────────────────────────────────────
    CommandFlowLifecycle(CommandFlowLifecycle),
    ConnectFlowLifecycle(ConnectFlowLifecycle),
    KernelFlowLifecycle(KernelFlowLifecycle),
    NotificationFlowLifecycle(NotificationFlowLifecycle),
    ServiceObserverLifecycle(ServiceObserverLifecycle),
    StatsFlowLifecycle(StatsFlowLifecycle),
    SubscriptionFlowLifecycle(SubscriptionFlowLifecycle),
    VerdictFlowLifecycle(VerdictFlowLifecycle),

    // ── Flow actions ───────────────────────────────────────────────────────
    ConnectFlowAction(ConnectFlowAction),
    KernelFlowAction(KernelFlowAction),
    StatsFlowAction(StatsFlowAction),
}

impl std::fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // ── Audit ──────────────────────────────────────────────────────
            Self::AuditLifecycle(v) => match v {
                AuditLifecycle::Initialized => f.write_str("AuditLifecycle/Initialized"),
                AuditLifecycle::SinkStarted => f.write_str("AuditLifecycle/SinkStarted"),
                AuditLifecycle::Stopped => f.write_str("AuditLifecycle/Stopped"),
            },

            // ── Client ─────────────────────────────────────────────────────
            Self::ClientLifecycle(v) => match v {
                ClientLifecycle::Initialized => f.write_str("ClientLifecycle/Initialized"),
                ClientLifecycle::Started => f.write_str("ClientLifecycle/Started"),
                ClientLifecycle::Stopped => f.write_str("ClientLifecycle/Stopped"),
                ClientLifecycle::ReloadStarted => f.write_str("ClientLifecycle/ReloadStarted"),
                ClientLifecycle::ReloadCompleted => f.write_str("ClientLifecycle/ReloadCompleted"),
                ClientLifecycle::ReloadFailed { reason } => {
                    write!(f, "ClientLifecycle/ReloadFailed[reason={reason}]")
                }
                ClientLifecycle::NotificationFlowStarted => {
                    f.write_str("ClientLifecycle/NotificationFlowStarted")
                }
                ClientLifecycle::CommandFlowStarted => {
                    f.write_str("ClientLifecycle/CommandFlowStarted")
                }
            },
            Self::ClientAuthorizationAction(v) => match v {
                ClientAuthorizationAction::DeniedOwnerScopeRules {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/DeniedOwnerScopeRules[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::DeniedOwnerScopeFirewall {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/DeniedOwnerScopeFirewall[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::DeniedAuthorizationPolicy {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/DeniedAuthorizationPolicy[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::AllowedOwnerScopeRules {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/AllowedOwnerScopeRules[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::AllowedOwnerScopeFirewall {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/AllowedOwnerScopeFirewall[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::AllowedAuthorizationPolicy {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/AllowedAuthorizationPolicy[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::AllowedRemoteCapability {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/AllowedRemoteCapability[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::DeniedRemoteCapability {
                    notification_id,
                    reason,
                    ..
                } => write!(
                    f,
                    "ClientAuthorizationAction/DeniedRemoteCapability[nid={notification_id},reason={reason}]"
                ),
                ClientAuthorizationAction::RemotePrincipalResolved { reason } => write!(
                    f,
                    "ClientAuthorizationAction/RemotePrincipalResolved[reason={reason}]"
                ),
            },

            // ── Config ─────────────────────────────────────────────────────
            Self::ConfigLifecycle(v) => match v {
                ConfigLifecycle::Initialized => f.write_str("ConfigLifecycle/Initialized"),
                ConfigLifecycle::Started => f.write_str("ConfigLifecycle/Started"),
                ConfigLifecycle::Stopped => f.write_str("ConfigLifecycle/Stopped"),
                ConfigLifecycle::ReloadStarted => f.write_str("ConfigLifecycle/ReloadStarted"),
                ConfigLifecycle::ReloadCompleted => f.write_str("ConfigLifecycle/ReloadCompleted"),
                ConfigLifecycle::ReloadFailed { reason } => {
                    write!(f, "ConfigLifecycle/ReloadFailed[reason={reason}]")
                }
            },
            Self::ConfigAction(v) => match v {
                ConfigAction::RuntimeTunablesLoaded => {
                    f.write_str("ConfigAction/RuntimeTunablesLoaded")
                }
                ConfigAction::FileRead { path } => {
                    write!(f, "ConfigAction/FileRead[path={path}]")
                }
                ConfigAction::FileWritten { path } => {
                    write!(f, "ConfigAction/FileWritten[path={path}]")
                }
                ConfigAction::FieldUpdated { key } => {
                    write!(f, "ConfigAction/FieldUpdated[key={key}]")
                }
                ConfigAction::ConfigApplied => f.write_str("ConfigAction/ConfigApplied"),
                ConfigAction::UpdateFailed { reason } => {
                    write!(f, "ConfigAction/UpdateFailed[reason={reason}]")
                }
            },

            // ── Connection ─────────────────────────────────────────────────
            Self::ConnectionLifecycle(v) => match v {
                ConnectionLifecycle::Initialized => f.write_str("ConnectionLifecycle/Initialized"),
                ConnectionLifecycle::Started => f.write_str("ConnectionLifecycle/Started"),
                ConnectionLifecycle::Stopped => f.write_str("ConnectionLifecycle/Stopped"),
                ConnectionLifecycle::Failed { reason } => {
                    write!(f, "ConnectionLifecycle/Failed[reason={reason}]")
                }
                ConnectionLifecycle::WorkersConfigured => {
                    f.write_str("ConnectionLifecycle/WorkersConfigured")
                }
            },

            // ── DNS ────────────────────────────────────────────────────────
            Self::DnsLifecycle(v) => match v {
                DnsLifecycle::Initialized => f.write_str("DnsLifecycle/Initialized"),
                DnsLifecycle::Started => f.write_str("DnsLifecycle/Started"),
                DnsLifecycle::Stopped => f.write_str("DnsLifecycle/Stopped"),
                DnsLifecycle::Failed { reason } => {
                    write!(f, "DnsLifecycle/Failed[reason={reason}]")
                }
                DnsLifecycle::WorkersConfigured => f.write_str("DnsLifecycle/WorkersConfigured"),
            },
            Self::DnsAction(v) => match v {
                DnsAction::CacheUpdated { entries } => {
                    write!(f, "DnsAction/CacheUpdated[entries={entries}]")
                }
                DnsAction::CacheEvicted { entries } => {
                    write!(f, "DnsAction/CacheEvicted[entries={entries}]")
                }
                DnsAction::ResolutionReceived { hostname } => {
                    write!(f, "DnsAction/ResolutionReceived[host={hostname}]")
                }
                DnsAction::ResolutionFailed { hostname, reason } => {
                    write!(
                        f,
                        "DnsAction/ResolutionFailed[host={hostname},reason={reason}]"
                    )
                }
            },

            // ── Firewall ───────────────────────────────────────────────────
            Self::FirewallLifecycle(v) => match v {
                FirewallLifecycle::Initialized => f.write_str("FirewallLifecycle/Initialized"),
                FirewallLifecycle::Started => f.write_str("FirewallLifecycle/Started"),
                FirewallLifecycle::Stopped => f.write_str("FirewallLifecycle/Stopped"),
                FirewallLifecycle::ReloadStarted => f.write_str("FirewallLifecycle/ReloadStarted"),
                FirewallLifecycle::ReloadCompleted => {
                    f.write_str("FirewallLifecycle/ReloadCompleted")
                }
                FirewallLifecycle::ReloadFailed { reason } => {
                    write!(f, "FirewallLifecycle/ReloadFailed[reason={reason}]")
                }
                FirewallLifecycle::HealStarted => f.write_str("FirewallLifecycle/HealStarted"),
                FirewallLifecycle::HealCompleted => f.write_str("FirewallLifecycle/HealCompleted"),
                FirewallLifecycle::HealFailed { reason } => {
                    write!(f, "FirewallLifecycle/HealFailed[reason={reason}]")
                }
                FirewallLifecycle::WorkerStarted => f.write_str("FirewallLifecycle/WorkerStarted"),
            },
            Self::FirewallAction(v) => match v {
                FirewallAction::EnsureRulesApplied => {
                    f.write_str("FirewallAction/EnsureRulesApplied")
                }
                FirewallAction::EnsureRulesSkipped => {
                    f.write_str("FirewallAction/EnsureRulesSkipped")
                }
                FirewallAction::RuleAdded { chain, .. } => {
                    write!(f, "FirewallAction/RuleAdded[chain={chain}]")
                }
                FirewallAction::RuleDeleted { chain, .. } => {
                    write!(f, "FirewallAction/RuleDeleted[chain={chain}]")
                }
                FirewallAction::RuleAddFailed { chain, reason } => {
                    write!(
                        f,
                        "FirewallAction/RuleAddFailed[chain={chain},reason={reason}]"
                    )
                }
                FirewallAction::RuleDeleteFailed { chain, reason } => {
                    write!(
                        f,
                        "FirewallAction/RuleDeleteFailed[chain={chain},reason={reason}]"
                    )
                }
                FirewallAction::ChainAdded { chain } => {
                    write!(f, "FirewallAction/ChainAdded[chain={chain}]")
                }
                FirewallAction::ChainDeleted { chain } => {
                    write!(f, "FirewallAction/ChainDeleted[chain={chain}]")
                }
                FirewallAction::ChainFlushFailed { chain, reason } => {
                    write!(
                        f,
                        "FirewallAction/ChainFlushFailed[chain={chain},reason={reason}]"
                    )
                }
                FirewallAction::CommandFailed { reason } => {
                    write!(f, "FirewallAction/CommandFailed[reason={reason}]")
                }
            },

            // ── Kernel ─────────────────────────────────────────────────────
            Self::KernelAction(v) => match v {
                KernelAction::KernelPipelineDropsObserved {
                    dns,
                    process,
                    firewall,
                    total,
                } => {
                    write!(
                        f,
                        "KernelAction/KernelPipelineDropsObserved[dns={dns},proc={process},fw={firewall},total={total}]"
                    )
                }
                KernelAction::KernelInterfaceReattached { queue } => {
                    write!(f, "KernelAction/KernelInterfaceReattached[queue={queue}]")
                }
            },

            // ── Process ────────────────────────────────────────────────────
            Self::ProcessLifecycle(v) => match v {
                ProcessLifecycle::Initialized => f.write_str("ProcessLifecycle/Initialized"),
                ProcessLifecycle::Started => f.write_str("ProcessLifecycle/Started"),
                ProcessLifecycle::Stopped => f.write_str("ProcessLifecycle/Stopped"),
                ProcessLifecycle::Failed { reason } => {
                    write!(f, "ProcessLifecycle/Failed[reason={reason}]")
                }
                ProcessLifecycle::MonitorWorkersConfigured => {
                    f.write_str("ProcessLifecycle/MonitorWorkersConfigured")
                }
            },
            Self::ProcessAction(v) => match v {
                ProcessAction::ProcessTracked { pid } => {
                    write!(f, "ProcessAction/ProcessTracked[pid={pid}]")
                }
                ProcessAction::ProcessEvicted { pid } => {
                    write!(f, "ProcessAction/ProcessEvicted[pid={pid}]")
                }
                ProcessAction::ProcessScanFailed { pid, reason } => {
                    write!(
                        f,
                        "ProcessAction/ProcessScanFailed[pid={pid},reason={reason}]"
                    )
                }
            },

            // ── Rule ───────────────────────────────────────────────────────
            Self::RuleLifecycle(v) => match v {
                RuleLifecycle::Initialized => f.write_str("RuleLifecycle/Initialized"),
                RuleLifecycle::Started => f.write_str("RuleLifecycle/Started"),
                RuleLifecycle::Stopped => f.write_str("RuleLifecycle/Stopped"),
                RuleLifecycle::ReloadStarted => f.write_str("RuleLifecycle/ReloadStarted"),
                RuleLifecycle::ReloadCompleted => f.write_str("RuleLifecycle/ReloadCompleted"),
                RuleLifecycle::ReloadFailed { reason } => {
                    write!(f, "RuleLifecycle/ReloadFailed[reason={reason}]")
                }
            },
            Self::RuleAction(v) => match v {
                RuleAction::RulesLoaded => f.write_str("RuleAction/RulesLoaded"),
                RuleAction::RuleAdded { name } => {
                    write!(f, "RuleAction/RuleAdded[name={name}]")
                }
                RuleAction::RuleUpdated { name } => {
                    write!(f, "RuleAction/RuleUpdated[name={name}]")
                }
                RuleAction::RuleDeleted { name } => {
                    write!(f, "RuleAction/RuleDeleted[name={name}]")
                }
                RuleAction::RuleAddFailed { name, reason } => {
                    write!(f, "RuleAction/RuleAddFailed[name={name},reason={reason}]")
                }
                RuleAction::RuleUpdateFailed { name, reason } => {
                    write!(
                        f,
                        "RuleAction/RuleUpdateFailed[name={name},reason={reason}]"
                    )
                }
                RuleAction::RuleDeleteFailed { name, reason } => {
                    write!(
                        f,
                        "RuleAction/RuleDeleteFailed[name={name},reason={reason}]"
                    )
                }
                RuleAction::RuleCommandFailed {
                    notification_id,
                    reason,
                } => write!(
                    f,
                    "RuleAction/RuleCommandFailed[nid={notification_id},reason={reason}]"
                ),
            },

            // ── Stats ──────────────────────────────────────────────────────
            Self::StatsLifecycle(v) => match v {
                StatsLifecycle::Initialized => f.write_str("StatsLifecycle/Initialized"),
                StatsLifecycle::Started => f.write_str("StatsLifecycle/Started"),
                StatsLifecycle::Stopped => f.write_str("StatsLifecycle/Stopped"),
                StatsLifecycle::Failed { reason } => {
                    write!(f, "StatsLifecycle/Failed[reason={reason}]")
                }
                StatsLifecycle::FlowStarted => f.write_str("StatsLifecycle/FlowStarted"),
            },

            // ── Storage ────────────────────────────────────────────────────
            Self::StorageLifecycle(v) => match v {
                StorageLifecycle::Initialized => f.write_str("StorageLifecycle/Initialized"),
                StorageLifecycle::Started => f.write_str("StorageLifecycle/Started"),
                StorageLifecycle::Stopped => f.write_str("StorageLifecycle/Stopped"),
                StorageLifecycle::Failed { reason } => {
                    write!(f, "StorageLifecycle/Failed[reason={reason}]")
                }
                StorageLifecycle::StorageObserverLagged { skipped } => {
                    write!(
                        f,
                        "StorageLifecycle/StorageObserverLagged[skipped={skipped}]"
                    )
                }
                StorageLifecycle::StorageObserverRebound { reason } => {
                    write!(
                        f,
                        "StorageLifecycle/StorageObserverRebound[reason={reason}]"
                    )
                }
            },
            Self::StorageAction(v) => match v {
                StorageAction::FileRead { path } => {
                    write!(f, "StorageAction/FileRead[path={path}]")
                }
                StorageAction::FileWritten { path } => {
                    write!(f, "StorageAction/FileWritten[path={path}]")
                }
                StorageAction::FileReadFailed { path, reason } => {
                    write!(
                        f,
                        "StorageAction/FileReadFailed[path={path},reason={reason}]"
                    )
                }
                StorageAction::FileWriteFailed { path, reason } => {
                    write!(
                        f,
                        "StorageAction/FileWriteFailed[path={path},reason={reason}]"
                    )
                }
            },

            // ── Subscription ───────────────────────────────────────────────
            Self::SubscriptionLifecycle(v) => match v {
                SubscriptionLifecycle::Initialized => {
                    f.write_str("SubscriptionLifecycle/Initialized")
                }
                SubscriptionLifecycle::Started => f.write_str("SubscriptionLifecycle/Started"),
                SubscriptionLifecycle::Stopped => f.write_str("SubscriptionLifecycle/Stopped"),
                SubscriptionLifecycle::ReloadStarted => {
                    f.write_str("SubscriptionLifecycle/ReloadStarted")
                }
                SubscriptionLifecycle::ReloadCompleted => {
                    f.write_str("SubscriptionLifecycle/ReloadCompleted")
                }
                SubscriptionLifecycle::ReloadFailed { reason } => {
                    write!(f, "SubscriptionLifecycle/ReloadFailed[reason={reason}]")
                }
                SubscriptionLifecycle::SchedulerStarted => {
                    f.write_str("SubscriptionLifecycle/SchedulerStarted")
                }
            },
            Self::SubscriptionAction(v) => match v {
                SubscriptionAction::RefreshCompleted { name } => {
                    write!(f, "SubscriptionAction/RefreshCompleted[name={name}]")
                }
                SubscriptionAction::RefreshFailed { reason } => {
                    write!(f, "SubscriptionAction/RefreshFailed[reason={reason}]")
                }
            },

            // ── Task ───────────────────────────────────────────────────────
            Self::TaskLifecycle(v) => match v {
                TaskLifecycle::Initialized => f.write_str("TaskLifecycle/Initialized"),
                TaskLifecycle::Started => f.write_str("TaskLifecycle/Started"),
                TaskLifecycle::Stopped => f.write_str("TaskLifecycle/Stopped"),
                TaskLifecycle::ReloadStarted => f.write_str("TaskLifecycle/ReloadStarted"),
                TaskLifecycle::ReloadCompleted => f.write_str("TaskLifecycle/ReloadCompleted"),
                TaskLifecycle::ReloadFailed { reason } => {
                    write!(f, "TaskLifecycle/ReloadFailed[reason={reason}]")
                }
            },
            Self::TaskAction(v) => match v {
                TaskAction::RuntimeTasksStarted => f.write_str("TaskAction/RuntimeTasksStarted"),
                TaskAction::TaskPanicked { name } => {
                    write!(f, "TaskAction/TaskPanicked[name={name}]")
                }
                TaskAction::TaskRestarted { name } => {
                    write!(f, "TaskAction/TaskRestarted[name={name}]")
                }
                TaskAction::TaskRuntimePaused => f.write_str("TaskAction/TaskRuntimePaused"),
                TaskAction::TaskRuntimePauseFailed => {
                    f.write_str("TaskAction/TaskRuntimePauseFailed")
                }
                TaskAction::TaskRuntimeResumed => f.write_str("TaskAction/TaskRuntimeResumed"),
                TaskAction::TaskRuntimeResumeFailed => {
                    f.write_str("TaskAction/TaskRuntimeResumeFailed")
                }
                TaskAction::TaskRuntimeStopped => f.write_str("TaskAction/TaskRuntimeStopped"),
                TaskAction::TaskRuntimeStopFailed => {
                    f.write_str("TaskAction/TaskRuntimeStopFailed")
                }
            },

            // ── Verdict ────────────────────────────────────────────────────
            Self::VerdictAction(v) => match v {
                VerdictAction::AskTimeoutFallback { request_id, .. } => {
                    write!(f, "VerdictAction/AskTimeoutFallback[rid={request_id}]")
                }
                VerdictAction::AskRuleRulePersisted {
                    request_id,
                    rule_name,
                    ..
                } => {
                    write!(
                        f,
                        "VerdictAction/AskRuleRulePersisted[rid={request_id},rule={rule_name}]"
                    )
                }
                VerdictAction::VerdictQueueBackpressure { request_id, source } => {
                    write!(
                        f,
                        "VerdictAction/VerdictQueueBackpressure[rid={request_id},src={}]",
                        source.as_name()
                    )
                }
            },

            // ── Flow lifecycles ────────────────────────────────────────────
            Self::CommandFlowLifecycle(v) => match v {
                CommandFlowLifecycle::Started => f.write_str("CommandFlowLifecycle/Started"),
                CommandFlowLifecycle::Stopped => f.write_str("CommandFlowLifecycle/Stopped"),
                CommandFlowLifecycle::Failed { reason } => {
                    write!(f, "CommandFlowLifecycle/Failed[reason={reason}]")
                }
            },
            Self::ConnectFlowLifecycle(v) => match v {
                ConnectFlowLifecycle::Started => f.write_str("ConnectFlowLifecycle/Started"),
                ConnectFlowLifecycle::Stopped => f.write_str("ConnectFlowLifecycle/Stopped"),
                ConnectFlowLifecycle::Failed { reason } => {
                    write!(f, "ConnectFlowLifecycle/Failed[reason={reason}]")
                }
            },
            Self::KernelFlowLifecycle(v) => match v {
                KernelFlowLifecycle::Started => f.write_str("KernelFlowLifecycle/Started"),
                KernelFlowLifecycle::Stopped => f.write_str("KernelFlowLifecycle/Stopped"),
                KernelFlowLifecycle::Failed { reason } => {
                    write!(f, "KernelFlowLifecycle/Failed[reason={reason}]")
                }
            },
            Self::NotificationFlowLifecycle(v) => match v {
                NotificationFlowLifecycle::Started => {
                    f.write_str("NotificationFlowLifecycle/Started")
                }
                NotificationFlowLifecycle::Stopped => {
                    f.write_str("NotificationFlowLifecycle/Stopped")
                }
                NotificationFlowLifecycle::Reconnected => {
                    f.write_str("NotificationFlowLifecycle/Reconnected")
                }
                NotificationFlowLifecycle::Failed => {
                    f.write_str("NotificationFlowLifecycle/Failed")
                }
            },
            Self::ServiceObserverLifecycle(v) => match v {
                ServiceObserverLifecycle::ServiceObserversStarted => {
                    f.write_str("ServiceObserverLifecycle/ServiceObserversStarted")
                }
                ServiceObserverLifecycle::ServiceObserversStopped => {
                    f.write_str("ServiceObserverLifecycle/ServiceObserversStopped")
                }
                ServiceObserverLifecycle::ServiceObserverFailed { name } => {
                    write!(
                        f,
                        "ServiceObserverLifecycle/ServiceObserverFailed[name={name}]"
                    )
                }
            },
            Self::StatsFlowLifecycle(v) => match v {
                StatsFlowLifecycle::Started => f.write_str("StatsFlowLifecycle/Started"),
                StatsFlowLifecycle::Stopped => f.write_str("StatsFlowLifecycle/Stopped"),
                StatsFlowLifecycle::Failed { reason } => {
                    write!(f, "StatsFlowLifecycle/Failed[reason={reason}]")
                }
            },
            Self::SubscriptionFlowLifecycle(v) => match v {
                SubscriptionFlowLifecycle::SchedulerStarted => {
                    f.write_str("SubscriptionFlowLifecycle/SchedulerStarted")
                }
                SubscriptionFlowLifecycle::StreamStarted => {
                    f.write_str("SubscriptionFlowLifecycle/StreamStarted")
                }
                SubscriptionFlowLifecycle::StreamStopped => {
                    f.write_str("SubscriptionFlowLifecycle/StreamStopped")
                }
                SubscriptionFlowLifecycle::StreamFailed { reason } => {
                    write!(f, "SubscriptionFlowLifecycle/StreamFailed[reason={reason}]")
                }
                SubscriptionFlowLifecycle::CommandStreamStarted => {
                    f.write_str("SubscriptionFlowLifecycle/CommandStreamStarted")
                }
                SubscriptionFlowLifecycle::CommandStreamFailed { reason } => {
                    write!(
                        f,
                        "SubscriptionFlowLifecycle/CommandStreamFailed[reason={reason}]"
                    )
                }
            },
            Self::VerdictFlowLifecycle(v) => match v {
                VerdictFlowLifecycle::Started => f.write_str("VerdictFlowLifecycle/Started"),
                VerdictFlowLifecycle::Stopped => f.write_str("VerdictFlowLifecycle/Stopped"),
                VerdictFlowLifecycle::Failed { reason } => {
                    write!(f, "VerdictFlowLifecycle/Failed[reason={reason}]")
                }
                VerdictFlowLifecycle::RepliesStarted => {
                    f.write_str("VerdictFlowLifecycle/RepliesStarted")
                }
            },

            // ── Flow actions ───────────────────────────────────────────────
            Self::ConnectFlowAction(v) => match v {
                ConnectFlowAction::ConnectionTracked => {
                    f.write_str("ConnectFlowAction/ConnectionTracked")
                }
                ConnectFlowAction::ConnectionDropped => {
                    f.write_str("ConnectFlowAction/ConnectionDropped")
                }
            },
            Self::KernelFlowAction(v) => match v {
                KernelFlowAction::PacketDropped => f.write_str("KernelFlowAction/PacketDropped"),
                KernelFlowAction::QueueOverflow { queue } => {
                    write!(f, "KernelFlowAction/QueueOverflow[queue={queue}]")
                }
            },
            Self::StatsFlowAction(v) => match v {
                StatsFlowAction::SnapshotPublished { connections } => {
                    write!(f, "StatsFlowAction/SnapshotPublished[conns={connections}]")
                }
            },
        }
    }
}

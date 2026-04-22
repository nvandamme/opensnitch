use crate::models::command_action::CommandAction;

/// Client service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum ClientLifecycle {
    Initialized,
    Started,
    Stopped,
    ReloadStarted,
    ReloadCompleted,
    ReloadFailed { reason: &'static str },
    NotificationFlowStarted,
    CommandFlowStarted,
}

/// Notification-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum NotificationFlowLifecycle {
    Started,
    Stopped,
    Reconnected,
    Failed,
}

/// Command-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum CommandFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
}

/// Control-plane authorization decision outcomes (runtime actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum ClientAuthorizationAction {
    DeniedOwnerScopeRules {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    DeniedOwnerScopeFirewall {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    DeniedAuthorizationPolicy {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    AllowedOwnerScopeRules {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    AllowedOwnerScopeFirewall {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    AllowedAuthorizationPolicy {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    /// Remote session allowed by capability-based authorization.
    AllowedRemoteCapability {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    /// Remote session denied: required capability not granted.
    DeniedRemoteCapability {
        notification_id: u64,
        action: CommandAction,
        reason: &'static str,
    },
    /// Remote principal binding resolved from TLS cert identity.
    RemotePrincipalResolved { reason: &'static str },
}

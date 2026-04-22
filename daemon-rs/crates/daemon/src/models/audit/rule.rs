/// Rule service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum RuleLifecycle {
    Initialized,
    Started,
    Stopped,
    ReloadStarted,
    ReloadCompleted,
    ReloadFailed { reason: &'static str },
}

/// Rule service runtime actions (CRUD and load).
#[derive(Debug, Clone)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum RuleAction {
    RulesLoaded,
    RuleAdded {
        name: Box<str>,
    },
    RuleUpdated {
        name: Box<str>,
    },
    RuleDeleted {
        name: Box<str>,
    },
    RuleAddFailed {
        name: Box<str>,
        reason: Box<str>,
    },
    RuleUpdateFailed {
        name: Box<str>,
        reason: Box<str>,
    },
    RuleDeleteFailed {
        name: Box<str>,
        reason: Box<str>,
    },
    /// The entire command-level policy transaction failed (rollback, conflict, etc.).
    RuleCommandFailed {
        notification_id: u64,
        reason: Box<str>,
    },
}

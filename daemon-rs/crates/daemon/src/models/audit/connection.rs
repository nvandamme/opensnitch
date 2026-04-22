/// Connection service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum ConnectionLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    WorkersConfigured,
}

/// Connect-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum ConnectFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
}

/// Connect-flow runtime actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum ConnectFlowAction {
    ConnectionTracked,
    ConnectionDropped,
}

/// Verdict-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum VerdictFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
    RepliesStarted,
}

/// Connection service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    WorkersConfigured,
}

/// Connect-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
}

/// Connect-flow runtime actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFlowAction {
    ConnectionTracked,
    ConnectionDropped,
}

/// Verdict-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
    RepliesStarted,
}

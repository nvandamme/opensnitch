/// Stats service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum StatsLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    FlowStarted,
}

/// Stats-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum StatsFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
}

/// Stats-flow runtime actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum StatsFlowAction {
    SnapshotPublished { connections: u32 },
}

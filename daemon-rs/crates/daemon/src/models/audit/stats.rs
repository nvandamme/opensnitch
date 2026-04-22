/// Stats service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    FlowStarted,
}

/// Stats-flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
}

/// Stats-flow runtime actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsFlowAction {
    SnapshotPublished { connections: u32 },
}

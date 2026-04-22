/// Process-monitor service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    MonitorWorkersConfigured,
}

/// Process-monitor service runtime actions (tracking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAction {
    ProcessTracked { pid: u32 },
    ProcessEvicted { pid: u32 },
    ProcessScanFailed { pid: u32, reason: &'static str },
}

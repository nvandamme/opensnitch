/// Task service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum TaskLifecycle {
    Initialized,
    Started,
    Stopped,
    ReloadStarted,
    ReloadCompleted,
    ReloadFailed { reason: &'static str },
}

/// Task service runtime actions (managed-task supervision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum TaskAction {
    RuntimeTasksStarted,
    TaskPanicked {
        name: &'static str,
    },
    TaskRestarted {
        name: &'static str,
    },
    /// The managed task runtime was paused via a control command.
    TaskRuntimePaused,
    /// A pause command was issued but the task runtime rejected it.
    TaskRuntimePauseFailed,
    /// The managed task runtime was resumed via a control command.
    TaskRuntimeResumed,
    /// A resume command was issued but the task runtime rejected it.
    TaskRuntimeResumeFailed,
    /// The managed task runtime was stopped via a control command.
    TaskRuntimeStopped,
    /// A stop command was issued but the task runtime rejected it.
    TaskRuntimeStopFailed,
}

/// Service lifecycle observer flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum ServiceObserverLifecycle {
    ServiceObserversStarted,
    ServiceObserversStopped,
    ServiceObserverFailed { name: &'static str },
}

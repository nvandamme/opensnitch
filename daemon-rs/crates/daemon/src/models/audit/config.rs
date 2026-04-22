/// Configuration service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLifecycle {
    Initialized,
    Started,
    Stopped,
    ReloadStarted,
    ReloadCompleted,
    ReloadFailed { reason: &'static str },
}

/// Configuration service runtime actions.
#[derive(Debug, Clone)]
pub enum ConfigAction {
    RuntimeTunablesLoaded,
    FileRead {
        path: Box<str>,
    },
    FileWritten {
        path: Box<str>,
    },
    FieldUpdated {
        key: &'static str,
    },
    /// A runtime config apply command succeeded (apply_config / daemon reload).
    ConfigApplied,
    /// A control command that mutates config or interception state failed.
    UpdateFailed {
        reason: Box<str>,
    },
}

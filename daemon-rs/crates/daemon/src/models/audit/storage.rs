/// Storage-observer service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum StorageLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    StorageObserverLagged { skipped: u64 },
    StorageObserverRebound { reason: &'static str },
}

/// Storage service runtime actions (file I/O).
#[derive(Debug, Clone)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum StorageAction {
    FileRead {
        path: Box<str>,
    },
    FileWritten {
        path: Box<str>,
    },
    FileReadFailed {
        path: Box<str>,
        reason: &'static str,
    },
    FileWriteFailed {
        path: Box<str>,
        reason: &'static str,
    },
}

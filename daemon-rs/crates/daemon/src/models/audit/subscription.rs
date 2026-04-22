/// Subscription service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum SubscriptionLifecycle {
    Initialized,
    Started,
    Stopped,
    ReloadStarted,
    ReloadCompleted,
    ReloadFailed { reason: &'static str },
    SchedulerStarted,
}

/// Subscription flow lifecycle transitions and sub-phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum SubscriptionFlowLifecycle {
    SchedulerStarted,
    StreamStarted,
    StreamStopped,
    StreamFailed { reason: &'static str },
    CommandStreamStarted,
    CommandStreamFailed { reason: &'static str },
}

/// Subscription service runtime actions (refresh outcomes).
#[derive(Debug, Clone)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum SubscriptionAction {
    RefreshCompleted { name: Box<str> },
    RefreshFailed { reason: Box<str> },
}

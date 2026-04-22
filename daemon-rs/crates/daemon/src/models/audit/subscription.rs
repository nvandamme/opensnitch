/// Subscription service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[cfg_attr(not(feature = "subscriptions"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionFlowLifecycle {
    SchedulerStarted,
    StreamStarted,
    StreamStopped,
    StreamFailed { reason: &'static str },
    CommandStreamStarted,
    CommandStreamFailed { reason: &'static str },
}

/// Subscription service runtime actions (refresh outcomes).
#[cfg_attr(not(feature = "subscriptions"), allow(dead_code))]
#[derive(Debug, Clone)]
pub enum SubscriptionAction {
    RefreshCompleted { name: Box<str> },
    RefreshFailed { reason: Box<str> },
}

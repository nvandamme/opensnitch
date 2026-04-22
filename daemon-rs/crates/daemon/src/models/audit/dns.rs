/// DNS service lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum DnsLifecycle {
    Initialized,
    Started,
    Stopped,
    Failed { reason: &'static str },
    WorkersConfigured,
}

/// DNS service runtime actions (cache and resolution).
#[derive(Debug, Clone)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum DnsAction {
    CacheUpdated {
        entries: u32,
    },
    CacheEvicted {
        entries: u32,
    },
    ResolutionReceived {
        hostname: Box<str>,
    },
    ResolutionFailed {
        hostname: Box<str>,
        reason: &'static str,
    },
}

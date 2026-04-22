#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ServiceState {
    #[default]
    Uninitialized,
    Running,
    Paused,
    #[cfg_attr(not(test), allow(dead_code))]
    Quiescing,
    Stopped,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ServiceStatus {
    pub state: ServiceState,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ServiceMonitorStats {
    pub status_subscribers: usize,
    pub event_subscribers: usize,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServiceEvent {
    StateChanged {
        from: ServiceState,
        to: ServiceState,
        last_error: Option<String>,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    HealthCheckFailed { error: String },
    #[cfg_attr(not(test), allow(dead_code))]
    Message { text: String },
}
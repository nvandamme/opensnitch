// Lifecycle contract vocabulary for all services. Not every variant is constructed yet —
// services are being wired up incrementally. Variants are the planned state/event surface
// per DESIGN_RULES.md §6 ("every domain signal enum must cover the full service lifecycle arc").
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ServiceState {
    #[default]
    Uninitialized,
    Running,
    Paused,
    // Planned lifecycle state: emitted when a service is draining in-flight work before stop.
    #[allow(dead_code)]
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

// Lifecycle contract event vocabulary. `StateChanged` is actively emitted; `HealthCheckFailed`
// is matched in lifecycle flow but not yet constructed by services; `Message` is planned.
// All variants are pre-declared per DESIGN_RULES.md §6 lifecycle coverage requirements.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServiceEvent {
    StateChanged {
        from: ServiceState,
        to: ServiceState,
        last_error: Option<String>,
    },
    // Planned event: emitted when a service health check loop detects degradation.
    #[allow(dead_code)]
    HealthCheckFailed { error: String },
    // Planned event: free-form diagnostic message for service-level observability.
    #[allow(dead_code)]
    Message { text: String },
}

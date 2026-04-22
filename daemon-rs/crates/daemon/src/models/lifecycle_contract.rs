// Lifecycle contract vocabulary for all services. Not every variant is constructed yet —
// services are being wired up incrementally. Variants are the planned state/event surface
// per DESIGN_RULES.md §6 ("every domain signal enum must cover the full service lifecycle arc").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
// Intentional lifecycle contract vocabulary across services; variants are phased in by service wiring.
#[allow(dead_code)]
pub(crate) enum ServiceState {
    #[default]
    Uninitialized,
    Running,
    Paused,
    // Planned lifecycle state: emitted when a service is draining in-flight work before stop.
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
#[derive(Debug, Clone, PartialEq, Eq)]
// Intentional lifecycle event contract surface; some variants are reserved for upcoming emit paths.
#[allow(dead_code)]
pub(crate) enum ServiceEvent {
    StateChanged {
        from: ServiceState,
        to: ServiceState,
        last_error: Option<String>,
    },
    // Planned event: emitted when a service health check loop detects degradation.
    HealthCheckFailed {
        error: String,
    },
    // Planned event: free-form diagnostic message for service-level observability.
    Message {
        text: String,
    },
}

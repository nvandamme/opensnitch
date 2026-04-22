#[derive(Debug, Clone, Copy)]
pub(crate) struct WorkerTelemetrySnapshot {
    pub state: &'static str,
    pub method: crate::config::ProcMonitorMethod,
    pub configured_handles: usize,
    pub running_handles: usize,
    pub shutdown_requested: bool,
}
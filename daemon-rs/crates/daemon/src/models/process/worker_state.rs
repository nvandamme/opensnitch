use crate::config::ProcMonitorMethod;

#[derive(Debug, Clone, Copy)]
pub struct ProcessWorkerState {
    pub requested_method: ProcMonitorMethod,
    pub worker_count: usize,
    pub ebpf_requested: bool,
    pub ebpf_available: bool,
}

impl Default for ProcessWorkerState {
    fn default() -> Self {
        Self {
            requested_method: ProcMonitorMethod::Proc,
            worker_count: 0,
            ebpf_requested: false,
            ebpf_available: false,
        }
    }
}

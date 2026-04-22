/// Kernel pipeline runtime action observations (health/pressure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAction {
    KernelPipelineDropsObserved {
        dns: u64,
        process: u64,
        firewall: u64,
        total: u64,
    },
    KernelInterfaceReattached {
        queue: u16,
    },
}

/// Kernel flow lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFlowLifecycle {
    Started,
    Stopped,
    Failed { reason: &'static str },
}

/// Kernel flow runtime actions (packet/queue observations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFlowAction {
    PacketDropped,
    QueueOverflow { queue: u16 },
}

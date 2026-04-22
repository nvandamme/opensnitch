#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Unknown,
    Running,
    Stopped,
}

impl WorkerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerJoinStatus {
    Stopped,
    Panicked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCommand {
    Start,
    Stop,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCommandResult {
    Applied,
    Unsupported,
}
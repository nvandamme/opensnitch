use std::sync::Arc;
use crate::models::{connection_state::ConnectionAttempt, process_state::ProcessInfo};

pub struct ConnectionContext {
    pub attempt: ConnectionAttempt,
    pub process: ProcessInfo,
    pub dst_host: Option<Arc<str>>,
}
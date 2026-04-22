use crate::models::{connection_state::ConnectionAttempt, process_state::ProcessInfo};
use std::sync::Arc;

pub struct ConnectionContext {
    pub attempt: ConnectionAttempt,
    pub process: ProcessInfo,
    pub dst_host: Option<Arc<str>>,
}

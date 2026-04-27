use crate::models::{connection::state::ConnectionAttempt, process::state::ProcessInfo};
use std::sync::Arc;

pub struct ConnectionContext {
    pub attempt: ConnectionAttempt,
    pub process: ProcessInfo,
    pub dst_host: Option<Arc<str>>,
}

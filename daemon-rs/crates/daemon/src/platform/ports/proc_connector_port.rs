use std::time::Duration;

use anyhow::Result;

use crate::{
    models::proc_event::ProcPidEvent, platform::adapters::proc_connector::ProcEventSocket,
};

pub(crate) trait ProcConnectorPlatformPort {
    fn open() -> Result<ProcEventSocket>;

    fn recv_pid_event(socket: &ProcEventSocket, timeout: Duration) -> Result<Option<ProcPidEvent>>;
}

pub(crate) struct NativeProcConnectorPort;

impl ProcConnectorPlatformPort for NativeProcConnectorPort {
    fn open() -> Result<ProcEventSocket> {
        ProcEventSocket::open()
    }

    fn recv_pid_event(socket: &ProcEventSocket, timeout: Duration) -> Result<Option<ProcPidEvent>> {
        socket.recv_pid_event(timeout)
    }
}

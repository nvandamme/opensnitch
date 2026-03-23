use anyhow::Result;

use crate::platform::adapters::proc_connector::ProcEventSocket;

pub(crate) trait ProcConnectorPlatformPort {
    fn open() -> Result<ProcEventSocket>;
}

pub(crate) struct NativeProcConnectorPort;

impl ProcConnectorPlatformPort for NativeProcConnectorPort {
    fn open() -> Result<ProcEventSocket> {
        ProcEventSocket::open()
    }
}

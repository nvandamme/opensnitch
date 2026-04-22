//! Port facade for audit netlink socket creation.

use anyhow::Result;

pub(crate) type AuditNetlinkSocketPort = crate::platform::adapters::audit_netlink::AuditNetlinkSocket;

pub(crate) struct AuditNetlinkPort;

impl AuditNetlinkPort {
    pub(crate) fn open() -> Result<AuditNetlinkSocketPort> {
        AuditNetlinkSocketPort::open()
    }
}

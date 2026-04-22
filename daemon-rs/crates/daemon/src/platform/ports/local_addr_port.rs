//! Port facade for local network address enumeration.
//!
//! Workers query local interface addresses through this port instead of
//! importing `platform::adapters::net_iface` directly.

use std::collections::HashSet;

use anyhow::Result;

use crate::platform::adapters::net_iface::NetIfaceAdapter;

pub(crate) struct LocalAddrPort;

impl LocalAddrPort {
    /// Returns the set of local IP addresses currently assigned to network
    /// interfaces, enumerated via netlink.
    pub(crate) async fn local_ip_addrs() -> Result<HashSet<String>> {
        NetIfaceAdapter::local_ip_addrs_async().await
    }
}

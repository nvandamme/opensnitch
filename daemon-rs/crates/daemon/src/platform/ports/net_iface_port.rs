//! Port facade for network interface name/address lookup.

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::platform::adapters::net_iface::NetIfaceAdapter;

pub(crate) struct NetIfacePort;

impl NetIfacePort {
    pub(crate) fn interface_name_by_index(index: u32) -> Result<Option<String>> {
        NetIfaceAdapter::interface_name_by_index(index)
    }

    pub(crate) async fn interface_name_by_index_async(index: u32) -> Result<Option<String>> {
        NetIfaceAdapter::interface_name_by_index_async(index).await
    }

    pub(crate) async fn interface_name_map_async() -> Result<HashMap<u32, String>> {
        NetIfaceAdapter::interface_name_map_async().await
    }

    #[allow(dead_code)]
    pub(crate) async fn local_ip_addrs_async() -> Result<HashSet<String>> {
        NetIfaceAdapter::local_ip_addrs_async().await
    }
}

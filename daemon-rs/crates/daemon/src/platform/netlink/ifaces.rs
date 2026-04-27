use std::{
    collections::{HashMap, HashSet},
    sync::{OnceLock, RwLock},
};

use anyhow::{Result, anyhow};
use netlink_bindings::{
    rt_addr::{self, Ifaddrmsg},
    rt_link::{self, Ifinfomsg},
};

use crate::platform::netlink::io::{
    ReplyVisit, for_each_reply, for_each_reply_until, netlink_map_io_error,
    netlink_map_reply_error, new_request_socket,
};

fn interface_name_cache() -> &'static RwLock<HashMap<u32, String>> {
    static CACHE: OnceLock<RwLock<HashMap<u32, String>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) struct NetIfaceAdapter;

impl NetIfaceAdapter {
    pub(crate) fn clear_interface_name_cache() {
        let mut cache = interface_name_cache()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.clear();
    }

    pub(crate) async fn local_ip_addrs_async() -> Result<HashSet<String>> {
        Self::local_ip_addrs_netlink_async_impl().await
    }

    #[cfg(test)]
    pub(crate) fn interface_name_map() -> Result<HashMap<u32, String>> {
        crate::platform::netlink::runtime::run_on_netlink_rt(
            Self::interface_name_map_netlink_async_impl(),
        )
    }

    pub(crate) async fn interface_name_map_async() -> Result<HashMap<u32, String>> {
        Self::interface_name_map_netlink_async_impl().await
    }

    pub(crate) fn interface_name_by_index(index: u32) -> Result<Option<String>> {
        crate::platform::netlink::runtime::run_on_netlink_rt(Self::interface_name_by_index_async(
            index,
        ))
    }

    pub(crate) async fn interface_name_by_index_async(index: u32) -> Result<Option<String>> {
        if index == 0 {
            return Ok(None);
        }

        if let Some(name) = {
            let cache = interface_name_cache()
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.get(&index).cloned()
        } {
            return Ok(Some(name));
        }

        match Self::interface_name_by_index_netlink_async_impl(index).await {
            Ok(Some(name)) => {
                Self::cache_insert(index, &name);
                Ok(Some(name))
            }
            Ok(None) => Ok(None),
            Err(_) => {
                let refreshed = Self::interface_name_map_async().await?;
                let hit = refreshed.get(&index).cloned();
                Self::replace_cache(refreshed);
                Ok(hit)
            }
        }
    }

    fn cache_insert(index: u32, name: &str) {
        let mut cache = interface_name_cache()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.insert(index, name.to_string());
    }

    fn replace_cache(refreshed: HashMap<u32, String>) {
        let mut cache = interface_name_cache()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *cache = refreshed;
    }

    async fn interface_name_map_netlink_async_impl() -> Result<HashMap<u32, String>> {
        let header = Ifinfomsg::new();
        let request = rt_link::Request::new().op_getlink_dump(&header);
        let mut sock = new_request_socket();
        let mut map = HashMap::new();
        for_each_reply(
            &mut sock,
            &request,
            netlink_map_io_error!("RTM_GETLINK request", "net-iface netlink io error"),
            netlink_map_reply_error!("RTM_GETLINK reply", "net-iface netlink reply error"),
            |(msg, attrs)| {
                let Some(index) = u32::try_from(msg.ifi_index)
                    .ok()
                    .filter(|value| *value != 0)
                else {
                    return Ok(());
                };
                let Ok(name) = attrs.get_ifname() else {
                    return Ok(());
                };
                map.insert(index, name.to_string_lossy().into_owned());
                Ok(())
            },
        )
        .await?;

        Ok(map)
    }

    async fn interface_name_by_index_netlink_async_impl(index: u32) -> Result<Option<String>> {
        let mut header = Ifinfomsg::new();
        header.ifi_index = i32::try_from(index)
            .map_err(|_| anyhow!("interface index {index} does not fit into ifi_index"))?;
        let request = rt_link::Request::new().op_getlink_do(&header);
        let mut sock = new_request_socket();
        let hit = for_each_reply_until(
            &mut sock,
            &request,
            netlink_map_io_error!("RTM_GETLINK do request", "net-iface netlink io error"),
            netlink_map_reply_error!("RTM_GETLINK do reply", "net-iface netlink reply error"),
            |(msg, attrs)| {
                let Some(reply_index) = u32::try_from(msg.ifi_index)
                    .ok()
                    .filter(|value| *value != 0)
                else {
                    return Ok(ReplyVisit::Continue);
                };
                if reply_index != index {
                    return Ok(ReplyVisit::Continue);
                }
                let Ok(name) = attrs.get_ifname() else {
                    return Ok(ReplyVisit::Continue);
                };
                Ok(ReplyVisit::Break(name.to_string_lossy().into_owned()))
            },
        )
        .await?;
        Ok(hit)
    }

    async fn local_ip_addrs_netlink_async_impl() -> Result<HashSet<String>> {
        let header = Ifaddrmsg::new();
        let request = rt_addr::Request::new().op_getaddr_dump(&header);
        let mut sock = new_request_socket();
        let mut out = HashSet::new();
        for_each_reply(
            &mut sock,
            &request,
            netlink_map_io_error!("RTM_GETADDR request", "net-iface netlink io error"),
            netlink_map_reply_error!("RTM_GETADDR reply", "net-iface netlink reply error"),
            |(msg, attrs)| {
                let Some(addr) = attrs.get_local().or_else(|_| attrs.get_address()).ok() else {
                    return Ok(());
                };

                match msg.ifa_family as i32 {
                    nix::libc::AF_INET if addr.is_ipv4() => {
                        out.insert(addr.to_string());
                    }
                    nix::libc::AF_INET6 if addr.is_ipv6() => {
                        out.insert(addr.to_string());
                    }
                    _ => {}
                }
                Ok(())
            },
        )
        .await?;

        Ok(out)
    }
}

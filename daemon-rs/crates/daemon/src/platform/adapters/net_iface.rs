use std::{
    collections::{HashMap, HashSet},
    sync::{OnceLock, RwLock},
};

use anyhow::Result;
#[cfg(feature = "netlink-bindings-socket-diag")]
use netlink_bindings::{
    rt_addr::{self, Ifaddrmsg},
    rt_link::{self, Ifinfomsg},
};
#[cfg(feature = "netlink-bindings-socket-diag")]
use netlink_socket2::{NetlinkSocket, ReplyError};

fn interface_name_cache() -> &'static RwLock<HashMap<u32, String>> {
    static CACHE: OnceLock<RwLock<HashMap<u32, String>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) struct NetIfaceAdapter;

impl NetIfaceAdapter {
    pub(crate) async fn local_ip_addrs_async() -> Result<HashSet<String>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return Self::local_ip_addrs_netlink_async_impl().await;
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            anyhow::bail!("net iface lookups require feature netlink-bindings-socket-diag")
        }
    }

    pub(crate) fn interface_name_map() -> Result<HashMap<u32, String>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return super::netlink_rt::run_on_netlink_rt(Self::interface_name_map_netlink_async_impl());
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            anyhow::bail!("net iface lookups require feature netlink-bindings-socket-diag")
        }
    }

    pub(crate) async fn interface_name_map_async() -> Result<HashMap<u32, String>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return Self::interface_name_map_netlink_async_impl().await;
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            anyhow::bail!("net iface lookups require feature netlink-bindings-socket-diag")
        }
    }

    pub(crate) fn interface_name_by_index(index: u32) -> Result<Option<String>> {
        if index == 0 {
            return Ok(None);
        }

        if let Ok(cache) = interface_name_cache().read()
            && let Some(name) = cache.get(&index)
        {
            return Ok(Some(name.clone()));
        }

        let refreshed = Self::interface_name_map()?;
        let hit = refreshed.get(&index).cloned();
        if let Ok(mut cache) = interface_name_cache().write() {
            *cache = refreshed;
        }
        Ok(hit)
    }

    pub(crate) async fn interface_name_by_index_async(index: u32) -> Result<Option<String>> {
        if index == 0 {
            return Ok(None);
        }

        if let Ok(cache) = interface_name_cache().read()
            && let Some(name) = cache.get(&index)
        {
            return Ok(Some(name.clone()));
        }

        let refreshed = Self::interface_name_map_async().await?;
        let hit = refreshed.get(&index).cloned();
        if let Ok(mut cache) = interface_name_cache().write() {
            *cache = refreshed;
        }
        Ok(hit)
    }

    #[cfg(feature = "netlink-bindings-socket-diag")]
    async fn interface_name_map_netlink_async_impl() -> Result<HashMap<u32, String>> {
        let header = Ifinfomsg::new();
        let request = rt_link::Request::new().op_getlink_dump(&header);
        let mut sock = NetlinkSocket::new();
        let mut iter = sock
            .request(&request)
            .await
            .map_err(|err| Self::map_io_error("RTM_GETLINK request", err))?;
        let mut map = HashMap::new();

        while let Some(reply) = iter.recv().await {
            let (msg, attrs) =
                reply.map_err(|err| Self::map_reply_error("RTM_GETLINK reply", err))?;
            let Some(index) = u32::try_from(msg.ifi_index).ok().filter(|value| *value != 0) else {
                continue;
            };
            let Ok(name) = attrs.get_ifname() else {
                continue;
            };
            map.insert(index, name.to_string_lossy().into_owned());
        }

        Ok(map)
    }

    #[cfg(feature = "netlink-bindings-socket-diag")]
    async fn local_ip_addrs_netlink_async_impl() -> Result<HashSet<String>> {
        let header = Ifaddrmsg::new();
        let request = rt_addr::Request::new().op_getaddr_dump(&header);
        let mut sock = NetlinkSocket::new();
        let mut iter = sock
            .request(&request)
            .await
            .map_err(|err| Self::map_io_error("RTM_GETADDR request", err))?;
        let mut out = HashSet::new();

        while let Some(reply) = iter.recv().await {
            let (msg, attrs) =
                reply.map_err(|err| Self::map_reply_error("RTM_GETADDR reply", err))?;
            let Some(addr) = attrs.get_local().or_else(|_| attrs.get_address()).ok() else {
                continue;
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
        }

        Ok(out)
    }

    #[cfg(feature = "netlink-bindings-socket-diag")]
    fn map_io_error(action: &'static str, err: std::io::Error) -> anyhow::Error {
        tracing::warn!(action, detail = %err, "net-iface netlink io error");
        anyhow::Error::new(err)
    }

    #[cfg(feature = "netlink-bindings-socket-diag")]
    fn map_reply_error(action: &'static str, err: ReplyError) -> anyhow::Error {
        Self::log_reply_error(action, &err);
        anyhow::Error::new(err)
    }

    #[cfg(feature = "netlink-bindings-socket-diag")]
    fn log_reply_error(action: &'static str, err: &ReplyError) {
        let errno = err.as_io_error().raw_os_error().unwrap_or_default();
        let extack_message = err
            .ext_ack()
            .and_then(|attrs| attrs.get_msg().ok())
            .map(|msg| msg.to_string_lossy().into_owned())
            .unwrap_or_else(|| "-".to_string());

        tracing::warn!(
            action,
            errno,
            extack = extack_message,
            detail = %err,
            "net-iface netlink reply error"
        );
    }
}
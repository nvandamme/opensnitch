use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;

use crate::models::socket_state::SocketInfo;

pub(crate) struct SocketDiagAdapter;

impl SocketDiagAdapter {
    fn socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        let mut cookie = [0_u8; 8];
        cookie[..4].copy_from_slice(&socket.cookie0.to_ne_bytes());
        cookie[4..].copy_from_slice(&socket.cookie1.to_ne_bytes());
        cookie
    }

    fn decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        (
            u32::from_ne_bytes([cookie[0], cookie[1], cookie[2], cookie[3]]),
            u32::from_ne_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]),
        )
    }

    fn select_socket_candidates(
        sockets: &[SocketInfo],
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Vec<SocketInfo> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        for s in sockets {
            if s.src_port == src_port && s.dst_port == dst_port && s.src == src && s.dst == dst {
                if seen.insert((s.inode, s.uid, s.src_port, s.dst_port)) {
                    out.push(s.clone());
                }
            }
        }

        // Go parity fallback: include wildcard destination rows as potential matches.
        for s in sockets {
            if s.src_port == src_port && s.src == src && s.dst_port == 0 && s.dst.is_unspecified() {
                if seen.insert((s.inode, s.uid, s.src_port, s.dst_port)) {
                    out.push(s.clone());
                }
            }
        }

        // Go parity fallback: include same src/src-port/dst-port rows even when destination IP differs.
        for s in sockets {
            if s.src_port == src_port && s.src == src && s.dst_port == dst_port {
                if seen.insert((s.inode, s.uid, s.src_port, s.dst_port)) {
                    out.push(s.clone());
                }
            }
        }

        out
    }

    #[allow(dead_code)]
    pub fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return super::socket_diag_bindings::SocketDiagBindingsAdapter::dump_sockets(
                family, protocol,
            );
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            let _ = (family, protocol);
            anyhow::bail!("socket-diag backend requires feature netlink-bindings-socket-diag")
        }
    }

    pub async fn dump_sockets_async(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return super::socket_diag_bindings::SocketDiagBindingsAdapter::dump_sockets_async(
                family, protocol,
            )
            .await;
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            tokio::task::spawn_blocking(move || Self::dump_sockets(family, protocol))
                .await
                .context("socket-diag dump task join failed")?
        }
    }

    pub fn find_socket(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Option<SocketInfo>> {
        let candidates =
            Self::find_socket_candidates(family, protocol, src, src_port, dst, dst_port)?;
        Ok(candidates.into_iter().next())
    }

    pub fn find_socket_candidates(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            let sockets = super::socket_diag_bindings::SocketDiagBindingsAdapter::find_socket_candidates_filtered(
                family, protocol, src, src_port, dst, dst_port,
            )?;
            return Ok(Self::select_socket_candidates(
                &sockets, src, src_port, dst, dst_port,
            ));
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            let sockets = Self::dump_sockets(family, protocol)?;
            Ok(Self::select_socket_candidates(
                &sockets, src, src_port, dst, dst_port,
            ))
        }
    }

    #[allow(dead_code)]
    pub async fn find_socket_candidates_async(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            let sockets = super::socket_diag_bindings::SocketDiagBindingsAdapter::find_socket_candidates_filtered_async(
                family, protocol, src, src_port, dst, dst_port,
            )
            .await?;
            return Ok(Self::select_socket_candidates(
                &sockets, src, src_port, dst, dst_port,
            ));
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            tokio::task::spawn_blocking(move || {
                Self::find_socket_candidates(family, protocol, src, src_port, dst, dst_port)
            })
            .await
            .context("socket-diag candidate task join failed")?
        }
    }

    pub fn kill_socket(family: u8, protocol: u8, socket: &SocketInfo) -> Result<()> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return super::socket_diag_bindings::SocketDiagBindingsAdapter::kill_socket(
                family, protocol, socket,
            );
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            let _ = (family, protocol, socket);
            anyhow::bail!("socket-diag backend requires feature netlink-bindings-socket-diag")
        }
    }

    #[allow(dead_code)]
    pub async fn kill_socket_async(family: u8, protocol: u8, socket: SocketInfo) -> Result<()> {
        #[cfg(feature = "netlink-bindings-socket-diag")]
        {
            return super::socket_diag_bindings::SocketDiagBindingsAdapter::kill_socket_async(
                family, protocol, socket,
            )
            .await;
        }

        #[cfg(not(feature = "netlink-bindings-socket-diag"))]
        {
            tokio::task::spawn_blocking(move || Self::kill_socket(family, protocol, &socket))
                .await
                .context("socket-diag kill task join failed")?
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        Self::socket_cookie_bytes(socket)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        Self::decode_cookie_words(cookie)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_select_socket_candidates(
        sockets: &[SocketInfo],
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Vec<SocketInfo> {
        Self::select_socket_candidates(sockets, src, src_port, dst, dst_port)
    }
}

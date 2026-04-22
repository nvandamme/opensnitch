use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;

use crate::models::socket_state::SocketInfo;

pub(crate) struct SocketDiagAdapter;

impl SocketDiagAdapter {
    #[cfg(test)]
    fn socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        let mut cookie = [0_u8; 8];
        cookie[..4].copy_from_slice(&socket.cookie0.to_ne_bytes());
        cookie[4..].copy_from_slice(&socket.cookie1.to_ne_bytes());
        cookie
    }

    #[cfg(test)]
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
        let mut exact = Vec::new();
        let mut wildcard_dst = Vec::new();
        let mut relaxed_dst = Vec::new();
        let mut seen = HashSet::new();

        for s in sockets {
            if s.src_port != src_port || s.src != src {
                continue;
            }

            let dedup_key = (s.inode, s.uid, s.src_port, s.dst_port);

            if s.dst_port == dst_port && s.dst == dst {
                if seen.insert(dedup_key) {
                    exact.push(s.clone());
                }
            } else if s.dst_port == 0 && s.dst.is_unspecified() {
                if seen.insert(dedup_key) {
                    wildcard_dst.push(s.clone());
                }
            } else if s.dst_port == dst_port {
                if seen.insert(dedup_key) {
                    relaxed_dst.push(s.clone());
                }
            }
        }

        exact.extend(wildcard_dst);
        exact.extend(relaxed_dst);
        exact
    }
    // Public compatibility helper retained for synchronous socket-diag callers.
    #[allow(dead_code)]
    pub fn dump_sockets(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        super::socket_diag_bindings::SocketDiagBindingsAdapter::dump_sockets(family, protocol)
    }

    pub async fn dump_sockets_async(family: u8, protocol: u8) -> Result<Vec<SocketInfo>> {
        super::socket_diag_bindings::SocketDiagBindingsAdapter::dump_sockets_async(family, protocol)
            .await
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
        let sockets = super::socket_diag_bindings::SocketDiagBindingsAdapter::find_socket_candidates_filtered(
            family, protocol, src, src_port, dst, dst_port,
        )?;
        Ok(Self::select_socket_candidates(
            &sockets, src, src_port, dst, dst_port,
        ))
    }
    pub async fn find_socket_candidates_async(
        family: u8,
        protocol: u8,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Result<Vec<SocketInfo>> {
        let sockets = super::socket_diag_bindings::SocketDiagBindingsAdapter::find_socket_candidates_filtered_async(
            family, protocol, src, src_port, dst, dst_port,
        )
        .await?;
        Ok(Self::select_socket_candidates(
            &sockets, src, src_port, dst, dst_port,
        ))
    }

    pub fn kill_socket(family: u8, protocol: u8, socket: &SocketInfo) -> Result<()> {
        super::socket_diag_bindings::SocketDiagBindingsAdapter::kill_socket(
            family, protocol, socket,
        )
    }
    // Public compatibility helper retained for async socket-destroy call paths.
    #[allow(dead_code)]
    pub async fn kill_socket_async(family: u8, protocol: u8, socket: SocketInfo) -> Result<()> {
        super::socket_diag_bindings::SocketDiagBindingsAdapter::kill_socket_async(
            family, protocol, socket,
        )
        .await
    }
    #[cfg(test)]
    pub(crate) fn probe_socket_cookie_bytes(socket: &SocketInfo) -> [u8; 8] {
        Self::socket_cookie_bytes(socket)
    }
    #[cfg(test)]
    pub(crate) fn probe_decode_cookie_words(cookie: [u8; 8]) -> (u32, u32) {
        Self::decode_cookie_words(cookie)
    }
    #[cfg(test)]
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

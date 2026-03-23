#![cfg(feature = "netlink-bindings-socket-diag")]

use crate::models::socket_state::SocketInfo;
use crate::platform::adapters::socket_diag::SocketDiagAdapter;
use crate::platform::adapters::socket_diag_bindings::SocketDiagBindingsAdapter;
use nix::libc::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP};
use std::collections::HashSet;

fn socket_key(s: &SocketInfo) -> (u8, u16, u16, std::net::IpAddr, std::net::IpAddr, u32, u32) {
    (
        s.family, s.src_port, s.dst_port, s.src, s.dst, s.uid, s.inode,
    )
}

#[test]
fn socket_diag_backend_matrix_smoke() {
    let matrix = [
        (AF_INET as u8, IPPROTO_TCP as u8),
        (AF_INET6 as u8, IPPROTO_TCP as u8),
        (AF_INET as u8, IPPROTO_UDP as u8),
        (AF_INET6 as u8, IPPROTO_UDP as u8),
    ];

    for (family, protocol) in matrix {
        let bindings = SocketDiagBindingsAdapter::dump_sockets(family, protocol)
            .expect("netlink-bindings backend must complete");

        // A smoke contract: bindings backend must complete and yield stable keyable results.
        let _bindings_keys: HashSet<_> = bindings.iter().map(socket_key).collect();
    }
}

#[test]
fn socket_diag_adapter_prefers_bindings_under_feature() {
    let via_adapter = SocketDiagAdapter::dump_sockets(AF_INET as u8, IPPROTO_TCP as u8)
        .expect("adapter dump should succeed with feature enabled");
    let via_bindings = SocketDiagBindingsAdapter::dump_sockets(AF_INET as u8, IPPROTO_TCP as u8)
        .expect("bindings dump should succeed");

    if via_bindings.is_empty() {
        return;
    }

    let adapter_keys: HashSet<_> = via_adapter.iter().map(socket_key).collect();
    let bindings_keys: HashSet<_> = via_bindings.iter().map(socket_key).collect();
    let overlap = adapter_keys.intersection(&bindings_keys).count();

    assert!(
        overlap > 0,
        "adapter output should overlap bindings output when feature is enabled"
    );
}
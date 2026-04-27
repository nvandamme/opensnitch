use crate::platform::netstat::socket_diag::SocketDiagAdapter;
use crate::platform::netstat::socket_state::SocketInfo;
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
        let sockets = SocketDiagAdapter::dump_sockets(family, protocol)
            .expect("socket-diag backend must complete");

        // A smoke contract: backend must complete and yield stable keyable results.
        let _keys: HashSet<_> = sockets.iter().map(socket_key).collect();
    }
}

#[test]
fn socket_diag_sync_and_async_outputs_overlap() {
    let via_sync = SocketDiagAdapter::dump_sockets(AF_INET as u8, IPPROTO_TCP as u8)
        .expect("sync dump should succeed");
    let via_async = crate::platform::netlink::runtime::run_on_netlink_rt(
        SocketDiagAdapter::dump_sockets_async(AF_INET as u8, IPPROTO_TCP as u8),
    )
    .expect("async dump should succeed");

    if via_async.is_empty() {
        return;
    }

    let sync_keys: HashSet<_> = via_sync.iter().map(socket_key).collect();
    let async_keys: HashSet<_> = via_async.iter().map(socket_key).collect();
    let overlap = sync_keys.intersection(&async_keys).count();

    assert!(
        overlap > 0,
        "sync and async outputs should overlap for the same family/protocol"
    );
}

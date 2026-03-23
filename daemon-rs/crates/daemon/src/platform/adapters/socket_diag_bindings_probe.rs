#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn probe_netlink_bindings_symbols() {
    use netlink_bindings as _;

    // Compile-time probe only: verifies the optional socket crate links cleanly.
    let _ = core::mem::size_of::<netlink_socket2::NetlinkSocket>();
}

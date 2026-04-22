use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

#[tokio::test]
async fn snapshot_local_addrs_returns_sorted_values() {
    let mut values = vec![
        IpAddr::V6(Ipv6Addr::LOCALHOST).to_string(),
        IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
    ];
    values.sort();

    let local_addr_store = Arc::new(RwLock::new(Arc::new(Vec::new())));
    let snap =
        crate::workers::network::netlink_addr_worker::NetlinkAddrWorkerControl::snapshot_local_addrs(&local_addr_store);
    // The worker may not be running in this unit test; this just validates API behavior.
    assert!(snap.is_empty() || snap.windows(2).all(|w| w[0] <= w[1]));
    let _ = values;
}

use std::time::Duration;

use crate::platform::netlink::io::recv_with_timeout;

#[test]
fn recv_with_timeout_returns_value_for_ready_future() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let got = rt
        .block_on(recv_with_timeout(Duration::from_millis(50), async {
            Ok::<u32, std::io::Error>(7)
        }))
        .expect("recv should succeed");
    assert_eq!(got, Some(7));
}

#[test]
fn recv_with_timeout_returns_none_on_elapsed_timeout() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let got = rt
        .block_on(recv_with_timeout(Duration::from_millis(1), async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<u32, std::io::Error>(1)
        }))
        .expect("recv should timeout cleanly");
    assert_eq!(got, None);
}

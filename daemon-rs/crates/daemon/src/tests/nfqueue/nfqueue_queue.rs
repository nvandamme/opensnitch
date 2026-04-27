use anyhow::{Context, Result, anyhow};

use crate::platform::nfqueue::queue::should_fallback_to_ffi_backend;

#[test]
fn fallback_trigger_matches_socket_open_failure_context() {
    let err = anyhow!("socket(AF_NETLINK, SOCK_RAW, 12) failed: eperm");
    assert!(should_fallback_to_ffi_backend(&err));
}

#[test]
fn fallback_trigger_matches_error_chain_context() {
    let err = (|| -> Result<()> {
        Err(anyhow!("eperm"))
            .context("nfqueue open failed")
            .context("socket(AF_NETLINK, SOCK_RAW, 12) failed")
    })()
    .expect_err("error chain should fail");
    assert!(should_fallback_to_ffi_backend(&err));
}

#[test]
fn fallback_trigger_ignores_non_socket_open_errors() {
    let err = anyhow!("nfqueue netlink config error (seq=1, errno=1)");
    assert!(!should_fallback_to_ffi_backend(&err));
}

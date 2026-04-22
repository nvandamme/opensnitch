//! Port facade for the NFQUEUE netlink backend.
//!
//! Centralises the experiment-flag check, netlink recovery gate, and
//! backend-selection logic that previously lived in the nfqueue worker.
//! Workers call through this port instead of importing the adapter directly.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::platform::adapters::nfqueue_netlink;
use crate::platform::ffi::nfqueue;
use crate::tunables::RuntimeTunables;
use crate::utils::netlink_recovery::NetlinkRecoveryGate;

const NFQUEUE_NETLINK_RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(800);

static NFQUEUE_NETLINK_RECOVERY: NetlinkRecoveryGate =
    NetlinkRecoveryGate::new("nfqueue-netlink", NFQUEUE_NETLINK_RECOVERY_POLL_INTERVAL);
static NFQUEUE_NETLINK_REATTACH_PENDING: AtomicBool = AtomicBool::new(false);

pub(crate) struct NfqueueBackendPort;

impl NfqueueBackendPort {
    /// Returns `true` when the netlink backend experiment is enabled (default)
    /// and the recovery gate has not marked netlink as degraded.
    pub(crate) fn netlink_available() -> bool {
        nfqueue_netlink::nfqueue_netlink_experiment_enabled()
            && NFQUEUE_NETLINK_RECOVERY.is_available()
    }

    /// Run the best available NFQUEUE backend for `queue_num`.
    ///
    /// Prefers the pure-Rust netlink backend and falls back to the legacy FFI
    /// backend on startup errors or when the experiment flag is disabled.
    /// Marks the netlink backend as degraded on fallback so subsequent
    /// calls use FFI directly until the recovery probe succeeds.
    pub(crate) fn run<F>(
        queue_num: u16,
        shutdown: CancellationToken,
        on_reattached: F,
    ) -> Result<()>
    where
        F: FnOnce(u16),
    {
        if Self::netlink_available() {
            let result = nfqueue_netlink::NfqueueNetlinkAdapter::run(
                queue_num,
                shutdown.clone(),
                |queue_num| {
                    if NFQUEUE_NETLINK_REATTACH_PENDING.swap(false, Ordering::Relaxed) {
                        on_reattached(queue_num);
                    }
                },
            );

            if let Err(err) = result {
                let tunables = RuntimeTunables::global();
                let recovery_retry_ms = tunables.netlink_fallback_retry_delay_ms;
                let recovery_poll_ms = tunables.netlink_recovery_poll_interval_ms;
                if Self::should_fallback_to_legacy(&err) {
                    warn!(
                        queue_num,
                        detail = %err,
                        recovery_retry_ms,
                        recovery_poll_ms,
                        "nfqueue netlink startup timeout; falling back to legacy FFI backend"
                    );
                } else {
                    warn!(
                        queue_num,
                        detail = %err,
                        recovery_retry_ms,
                        recovery_poll_ms,
                        "nfqueue netlink startup failed; falling back to legacy FFI backend"
                    );
                }
                Self::mark_netlink_degraded();
                return nfqueue::NfqueueRuntimeState::run(queue_num, shutdown);
            }

            Ok(())
        } else {
            nfqueue::NfqueueRuntimeState::run(queue_num, shutdown)
        }
    }

    fn mark_netlink_degraded() {
        let tunables = RuntimeTunables::global();
        let retry_ms = tunables.netlink_fallback_retry_delay_ms as u64;
        let poll_ms = tunables.netlink_recovery_poll_interval_ms as u64;
        NFQUEUE_NETLINK_RECOVERY.set_retry_delay(Duration::from_millis(retry_ms));
        NFQUEUE_NETLINK_RECOVERY.set_poll_interval(Duration::from_millis(poll_ms));
        NFQUEUE_NETLINK_REATTACH_PENDING.store(true, Ordering::Relaxed);
        NFQUEUE_NETLINK_RECOVERY.mark_degraded(Self::netlink_recovery_probe);
    }

    fn netlink_recovery_probe() -> bool {
        nfqueue_netlink::NfqueueNetlinkAdapter::preflight().is_ok()
    }

    fn should_fallback_to_legacy(err: &anyhow::Error) -> bool {
        let message = err.to_string().to_ascii_lowercase();
        message.contains("ack timed out") || message.contains("request timed out")
    }
}

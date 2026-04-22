use std::{
    thread,
    thread::JoinHandle,
    time::Duration,
};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    bus::Bus, config::DefaultAction, platform::ffi::nfqueue,
    tunables::{NfqueueOverloadPolicy, RuntimeTunables},
};
use crate::platform::adapters::nfqueue_netlink;
use crate::utils::netlink_recovery::NetlinkRecoveryGate;

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(3);
const NFQUEUE_NETLINK_RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(800);
static NFQUEUE_NETLINK_RECOVERY: NetlinkRecoveryGate =
    NetlinkRecoveryGate::new("nfqueue-netlink", NFQUEUE_NETLINK_RECOVERY_POLL_INTERVAL);

pub(crate) struct NfqueueWorkerControl;

impl NfqueueWorkerControl {
    pub fn spawn(
        bus: Bus,
        queue_num: u16,
        default_action: DefaultAction,
        overload_policy: NfqueueOverloadPolicy,
        shutdown: CancellationToken,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            nfqueue::NfqueueRuntimeState::init(bus, queue_num, default_action, overload_policy);

            let repeat_shutdown = shutdown.clone();
            let repeat_queue_num = queue_num.saturating_add(1);
            let repeat_handle = thread::spawn(move || {
                if let Err(err) =
                    Self::run_queue_backend(repeat_queue_num, repeat_shutdown.clone())
                {
                    warn!("nfqueue repeat queue unavailable: {err}");
                    Self::wait_until_cancelled(&repeat_shutdown);
                }
            });

            match Self::run_queue_backend(queue_num, shutdown.clone()) {
                Ok(()) => info!("nfqueue worker exited"),
                Err(err) => {
                    warn!("nfqueue worker unavailable: {err}");
                    Self::wait_until_cancelled(&shutdown);
                }
            }

            crate::workers::join_thread_with_timeout(
                "nfqueue-repeat",
                repeat_handle,
                WORKER_JOIN_TIMEOUT,
                SHUTDOWN_POLL_INTERVAL,
            );
        })
    }

    fn wait_until_cancelled(shutdown: &CancellationToken) {
        while !shutdown.is_cancelled() {
            thread::sleep(SHUTDOWN_POLL_INTERVAL);
        }
    }

    /// Run the default netlink NFQUEUE backend (unless explicitly disabled by
    /// `OPENSNITCH_NFQUEUE_NETLINK_EXPERIMENT=0`) and gracefully fall back to
    /// the legacy FFI backend on startup errors.
    ///
    /// While degraded, subsequent startup attempts use legacy FFI directly; a
    /// short recovery loop clears degraded mode after netlink preflight recovers.
    fn run_queue_backend(
        queue_num: u16,
        shutdown: CancellationToken,
    ) -> anyhow::Result<()> {
        if nfqueue_netlink::nfqueue_netlink_experiment_enabled() && Self::netlink_available() {
            let netlink_result =
                nfqueue_netlink::NfqueueNetlinkAdapter::run(queue_num, shutdown.clone());

            if let Err(err) = netlink_result {
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

    fn netlink_available() -> bool {
        NFQUEUE_NETLINK_RECOVERY.is_available()
    }

    fn mark_netlink_degraded() {
        let tunables = RuntimeTunables::global();
        let retry_ms = tunables.netlink_fallback_retry_delay_ms as u64;
        let poll_ms = tunables.netlink_recovery_poll_interval_ms as u64;
        NFQUEUE_NETLINK_RECOVERY.set_retry_delay(Duration::from_millis(retry_ms));
        NFQUEUE_NETLINK_RECOVERY.set_poll_interval(Duration::from_millis(poll_ms));
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

use std::{thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::platform::ports::nfqueue_netlink_port::NfqueueBackendPort;
use crate::platform::ports::nfqueue_runtime_port::NfqueueRuntimePort;
use crate::{
    bus::Bus, config::DefaultAction, tunables::NfqueueOverloadPolicy,
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

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
            NfqueueRuntimePort::init(bus, queue_num, default_action, overload_policy);

            let repeat_shutdown = shutdown.clone();
            let repeat_queue_num = queue_num.saturating_add(1);
            let repeat_handle = thread::spawn(move || {
                if let Err(err) = Self::run_queue_backend(repeat_queue_num, repeat_shutdown.clone())
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
    fn run_queue_backend(queue_num: u16, shutdown: CancellationToken) -> anyhow::Result<()> {
        NfqueueBackendPort::run(queue_num, shutdown)
    }
}

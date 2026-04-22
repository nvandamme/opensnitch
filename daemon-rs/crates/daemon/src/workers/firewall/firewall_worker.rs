use std::{thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    bus::Bus,
    models::firewall_state::FirewallState,
    models::kernel_event::KernelEvent,
    services::firewall::{FirewallService, firewall_backend_name},
    workers::runtime::support::build_current_thread_runtime,
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct FirewallWorkerControl;

impl FirewallWorkerControl {
    pub fn spawn(
        bus: Bus,
        firewall: FirewallService,
        shutdown: CancellationToken,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let Some(rt) = build_current_thread_runtime("firewall worker runtime init failed")
            else {
                return;
            };

            let mut last_state: Option<FirewallState> = None;

            while !shutdown.is_cancelled() {
                rt.block_on(async {
                    if let Err(err) = firewall.heal_if_drifted().await {
                        warn!("failed to heal firewall drift: {err}");
                    }

                    let state = firewall.get_snapshot();
                    if last_state
                        .map(|prev| {
                            prev.enabled != state.state.enabled
                                || firewall_backend_name(prev.backend)
                                    != firewall_backend_name(state.state.backend)
                        })
                        .unwrap_or(true)
                    {
                        debug!(
                            enabled = state.state.enabled,
                            backend = firewall_backend_name(state.state.backend),
                            "firewall state changed"
                        );
                        let _ = crate::workers::dispatch_kernel_event_with_backoff(
                            &bus.kernel_tx,
                            KernelEvent::FirewallState(state.state),
                        );
                        last_state = Some(state.state);
                    }
                });

                if crate::workers::sleep_with_shutdown(
                    &shutdown,
                    Duration::from_secs(20),
                    SHUTDOWN_POLL_INTERVAL,
                ) {
                    break;
                }
            }
        })
    }
}

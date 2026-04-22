use std::{
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    bus::Bus, models::firewall_state::FirewallState, models::kernel_event::KernelEvent,
    services::firewall_service::FirewallService, workers::dispatch_kernel_event_with_backoff,
};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub fn spawn(bus: Bus, firewall: FirewallService, shutdown: CancellationToken) -> JoinHandle<()> {
    thread::spawn(move || {
        let rt = match Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(err) => {
                warn!("firewall worker runtime init failed: {err}");
                return;
            }
        };

        let mut last_state: Option<FirewallState> = None;

        while !shutdown.is_cancelled() {
            rt.block_on(async {
                if let Err(err) = firewall.heal_if_drifted().await {
                    warn!("failed to heal firewall drift: {err}");
                }

                let state = firewall.snapshot().await;
                if last_state
                    .map(|prev| {
                        prev.enabled != state.enabled
                            || prev.backend.as_str() != state.backend.as_str()
                    })
                    .unwrap_or(true)
                {
                    debug!(
                        enabled = state.enabled,
                        backend = state.backend.as_str(),
                        "firewall state changed"
                    );
                    let _ = dispatch_kernel_event_with_backoff(
                        &bus.kernel_tx,
                        KernelEvent::FirewallState(state),
                    );
                    last_state = Some(state);
                }
            });

            if sleep_with_shutdown(&shutdown, Duration::from_secs(20)) {
                break;
            }
        }
    })
}

fn sleep_with_shutdown(shutdown: &CancellationToken, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while !shutdown.is_cancelled() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }

        let remaining = deadline.saturating_duration_since(now);
        thread::sleep(remaining.min(SHUTDOWN_POLL_INTERVAL));
    }

    true
}

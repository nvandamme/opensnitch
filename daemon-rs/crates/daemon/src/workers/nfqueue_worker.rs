use std::{
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{bus::Bus, config::DefaultAction, ffi::nfqueue};

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

pub fn spawn(
    bus: Bus,
    queue_num: u16,
    default_action: DefaultAction,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    thread::spawn(move || {
        nfqueue::init(bus, queue_num, default_action);

        let repeat_shutdown = shutdown.clone();
        let repeat_queue_num = queue_num.saturating_add(1);
        let repeat_handle = thread::spawn(move || {
            if let Err(err) = nfqueue::run(repeat_queue_num, repeat_shutdown.clone()) {
                warn!("nfqueue repeat queue unavailable: {err}");
                wait_until_cancelled(&repeat_shutdown);
            }
        });

        match nfqueue::run(queue_num, shutdown.clone()) {
            Ok(()) => info!("nfqueue worker exited"),
            Err(err) => {
                warn!("nfqueue worker unavailable: {err}");
                wait_until_cancelled(&shutdown);
            }
        }

        join_with_timeout("nfqueue-repeat", repeat_handle);
    })
}

fn wait_until_cancelled(shutdown: &CancellationToken) {
    while !shutdown.is_cancelled() {
        thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }
}

fn join_with_timeout(name: &str, handle: JoinHandle<()>) {
    let started = Instant::now();
    while !handle.is_finished() && started.elapsed() < WORKER_JOIN_TIMEOUT {
        thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }

    if !handle.is_finished() {
        warn!(
            "{} thread did not stop within {:?}; detaching",
            name, WORKER_JOIN_TIMEOUT
        );
        return;
    }

    let _ = handle.join();
}

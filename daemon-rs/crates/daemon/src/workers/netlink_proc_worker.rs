use std::{thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::bus::Bus;

pub fn spawn(_bus: Bus, shutdown: CancellationToken) -> JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.is_cancelled() {
            thread::sleep(Duration::from_secs(60));
        }
    })
}

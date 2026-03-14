use std::{thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::services::dns_service::DnsService;

pub fn spawn(_dns: DnsService, shutdown: CancellationToken) -> JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.is_cancelled() {
            thread::sleep(Duration::from_secs(60));
        }
    })
}

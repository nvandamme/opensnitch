use std::{thread, thread::JoinHandle, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    bus::Bus,
    models::{
        connection::{ConnectionAttempt, TransportProtocol},
        event::KernelEvent,
    },
};

pub fn spawn(bus: Bus, shutdown: CancellationToken) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut next_id = 1_u64;

        loop {
            if shutdown.is_cancelled() {
                break;
            }

            let evt = ConnectionAttempt {
                request_id: next_id,
                protocol: TransportProtocol::Tcp,
                src_ip: "0.0.0.0".into(),
                src_port: 0,
                dst_ip: "1.1.1.1".into(),
                dst_port: 443,
                pid: 1234,
                uid: 1000,
                gid: 1000,
            };
            next_id += 1;

            if bus.kernel_tx.blocking_send(KernelEvent::ConnectAttempt(evt)).is_err() {
                break;
            }

            thread::sleep(Duration::from_secs(30));
        }
    })
}

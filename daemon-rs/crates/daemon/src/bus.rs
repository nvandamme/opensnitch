use tokio::sync::mpsc;

use crate::models::{event::KernelEvent, notification::ClientCommand, verdict::VerdictReply};

#[derive(Clone)]
pub struct Bus {
    pub kernel_tx: mpsc::Sender<KernelEvent>,
    pub client_cmd_tx: mpsc::Sender<ClientCommand>,
    pub verdict_tx: mpsc::Sender<VerdictReply>,
}

pub struct BusRx {
    pub kernel_rx: mpsc::Receiver<KernelEvent>,
    pub client_cmd_rx: mpsc::Receiver<ClientCommand>,
    pub verdict_rx: mpsc::Receiver<VerdictReply>,
}

pub fn build_bus(cap: usize) -> (Bus, BusRx) {
    let (kernel_tx, kernel_rx) = mpsc::channel(cap);
    let (client_cmd_tx, client_cmd_rx) = mpsc::channel(cap);
    let (verdict_tx, verdict_rx) = mpsc::channel(cap);

    (
        Bus {
            kernel_tx,
            client_cmd_tx,
            verdict_tx,
        },
        BusRx {
            kernel_rx,
            client_cmd_rx,
            verdict_rx,
        },
    )
}

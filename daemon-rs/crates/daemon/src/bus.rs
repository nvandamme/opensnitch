use tokio::sync::mpsc;

use opensnitch_proto::pb;

use crate::models::{
    command_rpc::ClientCommand, connection_state::ConnectionAttempt, kernel_event::KernelEvent,
    verdict_rpc::VerdictReply,
};

#[derive(Clone)]
pub struct Bus {
    pub connect_tx: mpsc::Sender<ConnectionAttempt>,
    pub kernel_tx: mpsc::Sender<KernelEvent>,
    pub client_cmd_tx: mpsc::Sender<ClientCommand>,
    pub verdict_tx: mpsc::Sender<VerdictReply>,
    pub task_reply_tx: mpsc::Sender<pb::NotificationReply>,
}

pub struct BusRx {
    pub connect_rx: mpsc::Receiver<ConnectionAttempt>,
    pub kernel_rx: mpsc::Receiver<KernelEvent>,
    pub client_cmd_rx: mpsc::Receiver<ClientCommand>,
    pub verdict_rx: mpsc::Receiver<VerdictReply>,
    pub task_reply_rx: mpsc::Receiver<pb::NotificationReply>,
}

pub fn build_bus(cap: usize) -> (Bus, BusRx) {
    let (connect_tx, connect_rx) = mpsc::channel(cap);
    let (kernel_tx, kernel_rx) = mpsc::channel(cap);
    let (client_cmd_tx, client_cmd_rx) = mpsc::channel(cap);
    let (verdict_tx, verdict_rx) = mpsc::channel(cap);
    let (task_reply_tx, task_reply_rx) = mpsc::channel(cap);

    (
        Bus {
            connect_tx,
            kernel_tx,
            client_cmd_tx,
            verdict_tx,
            task_reply_tx,
        },
        BusRx {
            connect_rx,
            kernel_rx,
            client_cmd_rx,
            verdict_rx,
            task_reply_rx,
        },
    )
}

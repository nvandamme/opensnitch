use tokio::sync::mpsc;

use crate::models::{
    command::rpc::ClientCommand, connection::state::ConnectionAttempt, kernel::event::KernelEvent,
    notification::alert::UiAlert, verdict::rpc::VerdictReply,
};

#[derive(Clone)]
pub struct Bus {
    pub connect_tx: mpsc::Sender<ConnectionAttempt>,
    pub kernel_tx: mpsc::Sender<KernelEvent>,
    pub client_cmd_tx: mpsc::Sender<ClientCommand>,
    pub verdict_tx: mpsc::Sender<VerdictReply>,
    pub task_reply_tx: mpsc::Sender<transport_wire_core::WireNotificationReply>,
    pub alert_tx: mpsc::Sender<UiAlert>,
}

pub struct BusRx {
    pub connect_rx: mpsc::Receiver<ConnectionAttempt>,
    pub kernel_rx: mpsc::Receiver<KernelEvent>,
    pub client_cmd_rx: mpsc::Receiver<ClientCommand>,
    pub verdict_rx: mpsc::Receiver<VerdictReply>,
    pub task_reply_rx: mpsc::Receiver<transport_wire_core::WireNotificationReply>,
    pub alert_rx: mpsc::Receiver<UiAlert>,
}

#[derive(Debug, Clone, Copy)]
pub struct BusCaps {
    pub connect: usize,
    pub kernel: usize,
    pub client_cmd: usize,
    pub verdict: usize,
    pub task_reply: usize,
    pub alert: usize,
}

impl BusCaps {
    pub const fn uniform(cap: usize) -> Self {
        Self {
            connect: cap,
            kernel: cap,
            client_cmd: cap,
            verdict: cap,
            task_reply: cap,
            alert: cap,
        }
    }
}

impl Default for BusCaps {
    fn default() -> Self {
        Self::uniform(512)
    }
}

pub struct BusState;

impl BusState {
    pub fn build_with_caps(caps: BusCaps) -> (Bus, BusRx) {
        let (connect_tx, connect_rx) = mpsc::channel(caps.connect);
        let (kernel_tx, kernel_rx) = mpsc::channel(caps.kernel);
        let (client_cmd_tx, client_cmd_rx) = mpsc::channel(caps.client_cmd);
        let (verdict_tx, verdict_rx) = mpsc::channel(caps.verdict);
        let (task_reply_tx, task_reply_rx) = mpsc::channel(caps.task_reply);
        let (alert_tx, alert_rx) = mpsc::channel(caps.alert);

        (
            Bus {
                connect_tx,
                kernel_tx,
                client_cmd_tx,
                verdict_tx,
                task_reply_tx,
                alert_tx,
            },
            BusRx {
                connect_rx,
                kernel_rx,
                client_cmd_rx,
                verdict_rx,
                task_reply_rx,
                alert_rx,
            },
        )
    }
}

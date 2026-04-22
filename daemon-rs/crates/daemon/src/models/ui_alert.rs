use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
};

use opensnitch_proto::pb;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum UiAlertData {
    Text(String),
    Connection(pb::Connection),
    Process(pb::Process),
}

#[derive(Debug, Clone)]
pub struct UiAlert {
    pub alert_type: i32,
    pub what: i32,
    pub action: i32,
    pub priority: i32,
    pub data: UiAlertData,
}

const ALERT_OVERFLOW_CAP: usize = 32;
static ALERT_OVERFLOW: OnceLock<Mutex<VecDeque<UiAlert>>> = OnceLock::new();

fn overflow_queue() -> &'static Mutex<VecDeque<UiAlert>> {
    ALERT_OVERFLOW.get_or_init(|| Mutex::new(VecDeque::with_capacity(ALERT_OVERFLOW_CAP)))
}

pub fn enqueue_alert(alert_tx: &mpsc::Sender<UiAlert>, alert: UiAlert) {
    match alert_tx.try_send(alert) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(alert)) => {
            if let Ok(mut queue) = overflow_queue().lock() {
                if queue.len() >= ALERT_OVERFLOW_CAP {
                    let _ = queue.pop_front();
                }
                queue.push_back(alert);
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

pub fn drain_overflow_alerts() -> Vec<UiAlert> {
    if let Ok(mut queue) = overflow_queue().lock() {
        queue.drain(..).collect()
    } else {
        Vec::new()
    }
}

impl UiAlert {
    pub fn info(text: impl Into<String>) -> Self {
        Self::generic_text(pb::alert::Type::Info, pb::alert::Priority::Low, text)
    }

    pub fn warning(text: impl Into<String>) -> Self {
        Self::generic_text(pb::alert::Type::Warning, pb::alert::Priority::Medium, text)
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self::generic_text(pb::alert::Type::Error, pb::alert::Priority::High, text)
    }

    pub fn warning_connection(conn: pb::Connection) -> Self {
        Self {
            alert_type: pb::alert::Type::Warning as i32,
            what: pb::alert::What::Connection as i32,
            action: pb::alert::Action::ShowAlert as i32,
            priority: pb::alert::Priority::Medium as i32,
            data: UiAlertData::Connection(conn),
        }
    }

    pub fn warning_process(proc: pb::Process) -> Self {
        Self {
            alert_type: pb::alert::Type::Warning as i32,
            what: pb::alert::What::KernelEvent as i32,
            action: pb::alert::Action::ShowAlert as i32,
            priority: pb::alert::Priority::Medium as i32,
            data: UiAlertData::Process(proc),
        }
    }

    fn generic_text(
        alert_type: pb::alert::Type,
        priority: pb::alert::Priority,
        text: impl Into<String>,
    ) -> Self {
        Self {
            alert_type: alert_type as i32,
            what: pb::alert::What::Generic as i32,
            action: pb::alert::Action::ShowAlert as i32,
            priority: priority as i32,
            data: UiAlertData::Text(text.into()),
        }
    }
}

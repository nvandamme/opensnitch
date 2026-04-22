use std::{
    sync::{Arc, Mutex},
};

use opensnitch_proto::pb;
use tokio::sync::mpsc;

use crate::models::ui_alert::{UiAlert, UiAlertData};
use crate::utils::ring_buffer::RingBuffer;

const ALERT_OVERFLOW_CAP: usize = 32;

#[derive(Clone)]
pub struct AlertBuffer {
    overflow: Arc<Mutex<RingBuffer<UiAlert>>>,
}

impl Default for AlertBuffer {
    fn default() -> Self {
        Self::with_capacity(ALERT_OVERFLOW_CAP)
    }
}

impl AlertBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            overflow: Arc::new(Mutex::new(RingBuffer::new(capacity.max(1)))),
        }
    }

    pub(crate) fn enqueue(&self, alert_tx: &mpsc::Sender<UiAlert>, alert: UiAlert) {
        match alert_tx.try_send(alert) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(alert)) => {
                if let Ok(mut queue) = self.overflow.lock() {
                    queue.push_overwrite(alert);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    pub(crate) fn drain_overflow_alerts(&self) -> Vec<UiAlert> {
        if let Ok(mut queue) = self.overflow.lock() {
            queue.drain_all()
        } else {
            Vec::new()
        }
    }
}

pub(crate) fn info_alert(text: impl Into<String>) -> UiAlert {
    generic_text_alert(pb::alert::Type::Info, pb::alert::Priority::Low, text)
}

pub(crate) fn warning_alert(text: impl Into<String>) -> UiAlert {
    generic_text_alert(pb::alert::Type::Warning, pb::alert::Priority::Medium, text)
}

pub(crate) fn error_alert(text: impl Into<String>) -> UiAlert {
    generic_text_alert(pb::alert::Type::Error, pb::alert::Priority::High, text)
}

pub(crate) fn warning_connection_alert(conn: pb::Connection) -> UiAlert {
    UiAlert {
        alert_type: pb::alert::Type::Warning as i32,
        what: pb::alert::What::Connection as i32,
        action: pb::alert::Action::ShowAlert as i32,
        priority: pb::alert::Priority::Medium as i32,
        data: UiAlertData::Connection(conn),
    }
}

pub(crate) fn warning_process_alert(proc: pb::Process) -> UiAlert {
    UiAlert {
        alert_type: pb::alert::Type::Warning as i32,
        what: pb::alert::What::KernelEvent as i32,
        action: pb::alert::Action::ShowAlert as i32,
        priority: pb::alert::Priority::Medium as i32,
        data: UiAlertData::Process(proc),
    }
}

pub(crate) fn enqueue_alert(
    alert_buffer: &AlertBuffer,
    alert_tx: &mpsc::Sender<UiAlert>,
    alert: UiAlert,
) {
    alert_buffer.enqueue(alert_tx, alert);
}

pub(crate) fn drain_overflow_alerts(alert_buffer: &AlertBuffer) -> Vec<UiAlert> {
    alert_buffer.drain_overflow_alerts()
}

fn generic_text_alert(
    alert_type: pb::alert::Type,
    priority: pb::alert::Priority,
    text: impl Into<String>,
) -> UiAlert {
    UiAlert {
        alert_type: alert_type as i32,
        what: pb::alert::What::Generic as i32,
        action: pb::alert::Action::ShowAlert as i32,
        priority: priority as i32,
        data: UiAlertData::Text(text.into()),
    }
}

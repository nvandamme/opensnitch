use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use transport_wire_core::{
    WireAlert, WireAlertAction, WireAlertData, WireAlertPriority, WireAlertType, WireAlertWhat,
    WireConnection, WireProcess, WireStringInt,
};

use crate::models::notification::alert::{
    UiAlert, UiAlertConnection, UiAlertData, UiAlertProcess, UiAlertStringInt,
};
use crate::utils::ring_buffer::RingBuffer;
use crate::utils::time_nonce::unix_epoch_nanos;

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
    generic_text_alert(WireAlertType::Info, WireAlertPriority::Low, text)
}

pub(crate) fn warning_alert(text: impl Into<String>) -> UiAlert {
    generic_text_alert(WireAlertType::Warning, WireAlertPriority::Medium, text)
}

pub(crate) fn error_alert(text: impl Into<String>) -> UiAlert {
    generic_text_alert(WireAlertType::Error, WireAlertPriority::High, text)
}

pub(crate) fn warning_connection_alert(conn: &WireConnection) -> UiAlert {
    UiAlert {
        alert_type: WireAlertType::Warning as i32,
        what: WireAlertWhat::Connection as i32,
        action: WireAlertAction::ShowAlert as i32,
        priority: WireAlertPriority::Medium as i32,
        data: UiAlertData::Connection(UiAlertConnection {
            protocol: conn.protocol.clone(),
            src_ip: conn.src_ip.clone(),
            src_port: conn.src_port,
            dst_ip: conn.dst_ip.clone(),
            dst_host: conn.dst_host.clone(),
            dst_port: conn.dst_port,
            user_id: conn.user_id,
            process_id: conn.process_id,
            process_path: conn.process_path.clone(),
            process_cwd: conn.process_cwd.clone(),
            process_args: conn.process_args.clone(),
            process_env: conn.process_env.clone(),
            process_checksums: conn.process_checksums.clone(),
            process_tree: conn
                .process_tree
                .iter()
                .map(|entry| UiAlertStringInt {
                    key: entry.key.clone(),
                    value: entry.value,
                })
                .collect(),
        }),
    }
}

pub(crate) fn warning_process_alert(proc: WireProcess) -> UiAlert {
    UiAlert {
        alert_type: WireAlertType::Warning as i32,
        what: WireAlertWhat::KernelEvent as i32,
        action: WireAlertAction::ShowAlert as i32,
        priority: WireAlertPriority::Medium as i32,
        data: UiAlertData::Process(UiAlertProcess {
            pid: proc.pid,
            ppid: proc.ppid,
            uid: proc.uid,
            comm: proc.comm,
            path: proc.path,
            args: proc.args,
            env: proc.env,
            cwd: proc.cwd,
            checksums: proc.checksums,
            io_reads: proc.io_reads,
            io_writes: proc.io_writes,
            net_reads: proc.net_reads,
            net_writes: proc.net_writes,
            process_tree: proc
                .process_tree
                .into_iter()
                .map(|entry| UiAlertStringInt {
                    key: entry.key,
                    value: entry.value,
                })
                .collect(),
        }),
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

pub(crate) fn build_wire_alert(alert: UiAlert) -> WireAlert {
    let UiAlert {
        alert_type,
        action,
        priority,
        what,
        data,
    } = alert;

    let data = match data {
        UiAlertData::Text(text) => WireAlertData::Text(text),
        UiAlertData::Connection(conn) => WireAlertData::Connection(WireConnection {
            protocol: conn.protocol,
            src_ip: conn.src_ip,
            src_port: conn.src_port,
            dst_ip: conn.dst_ip,
            dst_host: conn.dst_host,
            dst_port: conn.dst_port,
            user_id: conn.user_id,
            process_id: conn.process_id,
            process_path: conn.process_path,
            process_cwd: conn.process_cwd,
            process_args: conn.process_args,
            process_env: conn.process_env,
            process_checksums: conn.process_checksums,
            process_tree: conn
                .process_tree
                .into_iter()
                .map(|entry| WireStringInt {
                    key: entry.key,
                    value: entry.value,
                })
                .collect(),
        }),
        UiAlertData::Process(proc_info) => WireAlertData::Process(WireProcess {
            pid: proc_info.pid,
            ppid: proc_info.ppid,
            uid: proc_info.uid,
            comm: proc_info.comm,
            path: proc_info.path,
            args: proc_info.args,
            env: proc_info.env,
            cwd: proc_info.cwd,
            checksums: proc_info.checksums,
            io_reads: proc_info.io_reads,
            io_writes: proc_info.io_writes,
            net_reads: proc_info.net_reads,
            net_writes: proc_info.net_writes,
            process_tree: proc_info
                .process_tree
                .into_iter()
                .map(|entry| WireStringInt {
                    key: entry.key,
                    value: entry.value,
                })
                .collect(),
        }),
    };

    WireAlert {
        id: u64::try_from(unix_epoch_nanos()).unwrap_or(u64::MAX),
        alert_type,
        action,
        priority,
        what,
        data: Some(data),
    }
}

fn generic_text_alert(
    alert_type: WireAlertType,
    priority: WireAlertPriority,
    text: impl Into<String>,
) -> UiAlert {
    UiAlert {
        alert_type: alert_type as i32,
        what: WireAlertWhat::Generic as i32,
        action: WireAlertAction::ShowAlert as i32,
        priority: priority as i32,
        data: UiAlertData::Text(text.into()),
    }
}

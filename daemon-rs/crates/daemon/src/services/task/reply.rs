use std::sync::OnceLock;

use opensnitch_proto::pb;
use serde_json::Value;

use crate::models::{task_payload::LegacyTaskResultPayload, ui_alert::UiAlert};
use crate::services::client::{enqueue_alert, error_alert, info_alert};
use crate::utils::notification_reply::{is_ok_reply_code, send_notification_reply};

pub(crate) const DOWNLOADER_SUCCESS_MSG: &str = "[blocklists] lists updated";
static ALERT_TX: OnceLock<tokio::sync::mpsc::Sender<UiAlert>> = OnceLock::new();

pub(crate) fn configure_alert_sender(alert_tx: tokio::sync::mpsc::Sender<UiAlert>) {
    let _ = ALERT_TX.set(alert_tx);
}

pub(crate) fn build_legacy_downloader_task_result(data: &str) -> Value {
    serde_json::to_value(LegacyTaskResultPayload::new(data)).unwrap_or_else(|_| {
        serde_json::json!({
            "Type": LegacyTaskResultPayload::TYPE_ID,
            "Data": data,
        })
    })
}

pub(crate) async fn send_task_event(
    task_reply_tx: &tokio::sync::mpsc::Sender<pb::NotificationReply>,
    task_name: &str,
    notification_id: u64,
    code: pb::NotificationReplyCode,
    data: String,
) {
    let is_stream_notification = notification_id > 10_000;

    if is_stream_notification {
        let _ =
            send_notification_reply(task_reply_tx, notification_id, code, data, "task notification")
                .await;
        return;
    }

    let payload = data;
    crate::logging::LoggingState::forward_task_notification(
        task_name,
        &payload,
        !is_ok_reply_code(code),
    );

    if let Some(alert_tx) = ALERT_TX.get() {
        if is_ok_reply_code(code) {
            enqueue_alert(alert_tx, info_alert(payload));
        } else {
            enqueue_alert(alert_tx, error_alert(payload));
        }
    }
}

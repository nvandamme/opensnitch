use crate::models::{notification::alert::UiAlert, task::wire::LegacyTaskResultPayload};
use crate::services::client::{AlertBuffer, enqueue_alert, error_alert, info_alert};
use crate::utils::notification_reply::{is_ok_reply_code, send_notification_reply};

pub(crate) const DOWNLOADER_SUCCESS_MSG: &str = "[blocklists] lists updated";

pub(crate) fn build_legacy_downloader_task_result(data: &str) -> String {
    transport_wire_core::encode_json_notification_payload(&LegacyTaskResultPayload::new(data))
        .unwrap_or_else(|_| {
            format!(
                r#"{{"Type":{},"Data":{:?}}}"#,
                LegacyTaskResultPayload::TYPE_ID,
                data
            )
        })
}

pub(crate) async fn send_task_event(
    task_reply_tx: &tokio::sync::mpsc::Sender<transport_wire_core::WireNotificationReply>,
    alert_buffer: Option<&AlertBuffer>,
    alert_tx: Option<&tokio::sync::mpsc::Sender<UiAlert>>,
    task_name: &str,
    notification_id: u64,
    code: transport_wire_core::WireNotificationReplyCode,
    data: String,
) {
    let is_stream_notification = notification_id > 10_000;

    if is_stream_notification {
        let _ = send_notification_reply(
            task_reply_tx,
            notification_id,
            code,
            data,
            "task notification",
        )
        .await;
        return;
    }

    let payload = data;
    crate::logging::LoggingState::forward_task_notification(
        task_name,
        &payload,
        !is_ok_reply_code(code),
    );

    if let (Some(alert_buffer), Some(alert_tx)) = (alert_buffer, alert_tx) {
        if is_ok_reply_code(code) {
            enqueue_alert(alert_buffer, alert_tx, info_alert(payload));
        } else {
            enqueue_alert(alert_buffer, alert_tx, error_alert(payload));
        }
    }
}

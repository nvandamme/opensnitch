use opensnitch_proto::pb;
use tokio::sync::mpsc;

use crate::utils::channel_send::send_with_backpressure;

pub(crate) fn is_ok_reply_code(code: pb::NotificationReplyCode) -> bool {
    code == pb::NotificationReplyCode::Ok
}

pub(crate) fn status_payload(status: &str) -> String {
    serde_json::json!({"status": status}).to_string()
}

fn log_notification_reply(
    id: u64,
    code: pb::NotificationReplyCode,
    data: &str,
    log_label: &str,
) {
    if is_ok_reply_code(code) {
        tracing::info!(notification_id = id, reply_data = %data, "{log_label}");
    } else {
        tracing::error!(notification_id = id, reply_data = %data, "{log_label}");
    }
}

pub(crate) fn build_notification_reply(
    id: u64,
    code: pb::NotificationReplyCode,
    data: impl Into<String>,
) -> pb::NotificationReply {
    pb::NotificationReply {
        id,
        code: code as i32,
        data: data.into(),
    }
}

pub(crate) async fn send_notification_reply(
    reply_tx: &mpsc::Sender<pb::NotificationReply>,
    id: u64,
    code: pb::NotificationReplyCode,
    data: impl Into<String>,
    log_label: &str,
) -> bool {
    let data = data.into();
    log_notification_reply(id, code, &data, log_label);

    send_with_backpressure(reply_tx, build_notification_reply(id, code, data)).await
}
use tokio::sync::mpsc;
pub(crate) use transport_wire_core::status_payload;

use crate::utils::channel_send::send_with_backpressure;

pub(crate) fn is_ok_reply_code(code: transport_wire_core::WireNotificationReplyCode) -> bool {
    code == transport_wire_core::WireNotificationReplyCode::Ok
}

pub(crate) fn build_notification_reply(
    id: u64,
    code: transport_wire_core::WireNotificationReplyCode,
    data: impl Into<String>,
) -> transport_wire_core::WireNotificationReply {
    transport_wire_core::WireNotificationReply {
        id,
        code: code as i32,
        data: data.into(),
    }
}

fn log_notification_reply(
    id: u64,
    code: transport_wire_core::WireNotificationReplyCode,
    data: &str,
    log_label: &str,
) {
    if is_ok_reply_code(code) {
        tracing::info!(notification_id = id, reply_data = %data, "{log_label}");
    } else {
        tracing::error!(notification_id = id, reply_data = %data, "{log_label}");
    }
}

pub(crate) async fn send_notification_reply(
    reply_tx: &mpsc::Sender<transport_wire_core::WireNotificationReply>,
    id: u64,
    code: transport_wire_core::WireNotificationReplyCode,
    data: impl Into<String>,
    log_label: &str,
) -> bool {
    let data = data.into();
    log_notification_reply(id, code, &data, log_label);

    send_with_backpressure(reply_tx, build_notification_reply(id, code, data)).await
}

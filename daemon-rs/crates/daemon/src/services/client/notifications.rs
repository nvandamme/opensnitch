use anyhow::Result;
use tokio::sync::mpsc;
use transport_wire_core;
use transport_wire_core::NotificationInboundPort;
use transport_wire_core::{WireCommandAction, WireNotificationReply, WireNotificationReplyCode};

use super::client::ClientService;
use crate::models::command::action::CommandAction;

pub struct NotificationStream {
    pub inbound: Box<dyn NotificationInboundPort>,
    pub reply_tx: mpsc::Sender<WireNotificationReply>,
}

impl NotificationStream {
    pub async fn open(client: &mut ClientService) -> Result<Self> {
        let (inbound, reply_tx) = client.notification_stream_channels().await?;

        Ok(Self { inbound, reply_tx })
    }
}

pub(crate) fn notification_hello_reply_wire() -> WireNotificationReply {
    WireNotificationReply {
        id: 0,
        code: WireNotificationReplyCode::Ok as i32,
        data: String::new(),
    }
}

pub(crate) fn notification_error_reply_wire(
    notification_id: u64,
    message: impl Into<String>,
) -> WireNotificationReply {
    WireNotificationReply {
        id: notification_id,
        code: WireNotificationReplyCode::Error as i32,
        data: message.into(),
    }
}

pub(crate) fn command_action_from_notification_wire(action: i32) -> CommandAction {
    match WireCommandAction::from_i32(action) {
        WireCommandAction::None => CommandAction::None,
        WireCommandAction::EnableInterception => CommandAction::EnableInterception,
        WireCommandAction::DisableInterception => CommandAction::DisableInterception,
        WireCommandAction::EnableFirewall => CommandAction::EnableFirewall,
        WireCommandAction::DisableFirewall => CommandAction::DisableFirewall,
        WireCommandAction::ReloadFwRules => CommandAction::ReloadFwRules,
        WireCommandAction::ChangeConfig => CommandAction::ChangeConfig,
        WireCommandAction::EnableRule => CommandAction::EnableRule,
        WireCommandAction::DisableRule => CommandAction::DisableRule,
        WireCommandAction::DeleteRule => CommandAction::DeleteRule,
        WireCommandAction::ChangeRule => CommandAction::ChangeRule,
        WireCommandAction::TaskStart => CommandAction::TaskStart,
        WireCommandAction::TaskStop => CommandAction::TaskStop,
        WireCommandAction::LogLevel => CommandAction::LogLevel,
        WireCommandAction::Stop => CommandAction::Stop,
    }
}

pub(crate) fn is_stream_close_notification_wire(action: i32) -> bool {
    action <= WireCommandAction::None as i32
}

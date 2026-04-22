use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::mpsc;
#[cfg(feature = "grpc-ui")]
use tokio_stream::wrappers::ReceiverStream;

use super::client::ClientService;
use crate::models::command_action::CommandAction;
use crate::utils::notification_reply::build_notification_reply;

pub struct NotificationStream {
    pub inbound: tonic::Streaming<pb::Notification>,
    pub reply_tx: mpsc::Sender<pb::NotificationReply>,
}

impl NotificationStream {
    #[cfg(feature = "grpc-ui")]
    pub async fn open(client: &mut ClientService) -> Result<Self> {
        let (reply_tx, reply_rx) = mpsc::channel::<pb::NotificationReply>(64);
        let outbound = ReceiverStream::new(reply_rx);

        let response = client.grpc_mut().notifications(outbound).await?;
        let inbound = response.into_inner();

        Ok(Self { inbound, reply_tx })
    }

    #[cfg(not(feature = "grpc-ui"))]
    pub async fn open(_client: &mut ClientService) -> Result<Self> {
        anyhow::bail!(
            "grpc-ui feature disabled: Notifications stream transport is not available"
        )
    }
}

pub(crate) fn notification_hello_reply_wire() -> pb::NotificationReply {
    build_notification_reply(0, pb::NotificationReplyCode::Ok, String::new())
}

pub(crate) fn notification_error_reply_wire(
    notification_id: u64,
    message: impl Into<String>,
) -> pb::NotificationReply {
    build_notification_reply(notification_id, pb::NotificationReplyCode::Error, message.into())
}

pub(crate) fn command_action_from_notification_wire(action: i32) -> CommandAction {
    match pb::Action::try_from(action).unwrap_or(pb::Action::None) {
        pb::Action::None => CommandAction::None,
        pb::Action::EnableInterception => CommandAction::EnableInterception,
        pb::Action::DisableInterception => CommandAction::DisableInterception,
        pb::Action::EnableFirewall => CommandAction::EnableFirewall,
        pb::Action::DisableFirewall => CommandAction::DisableFirewall,
        pb::Action::ReloadFwRules => CommandAction::ReloadFwRules,
        pb::Action::ChangeConfig => CommandAction::ChangeConfig,
        pb::Action::EnableRule => CommandAction::EnableRule,
        pb::Action::DisableRule => CommandAction::DisableRule,
        pb::Action::DeleteRule => CommandAction::DeleteRule,
        pb::Action::ChangeRule => CommandAction::ChangeRule,
        pb::Action::TaskStart => CommandAction::TaskStart,
        pb::Action::TaskStop => CommandAction::TaskStop,
        pb::Action::LogLevel => CommandAction::LogLevel,
        pb::Action::Stop => CommandAction::Stop,
    }
}

pub(crate) fn is_stream_close_notification_wire(action: i32) -> bool {
    action <= pb::Action::None as i32
}

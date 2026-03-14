use anyhow::Result;
use opensnitch_proto::pb;

use crate::{
    bus::Bus,
    client::{client::Client, notifications::NotificationStream},
    models::notification::ClientCommand,
};

#[derive(Clone)]
pub struct NotificationFlow {
    bus: Bus,
    client: Client,
}

impl NotificationFlow {
    pub fn new(bus: Bus, client: Client) -> Self {
        Self { bus, client }
    }

    pub async fn run(mut self) -> Result<()> {
        let stream = NotificationStream::open(&mut self.client).await?;
        let mut inbound = stream.inbound;
        let reply_tx = stream.reply_tx;

        while let Some(notification) = inbound.message().await? {
            let cmd = match notification.r#type {
                x if x == pb::Action::EnableInterception as i32 => {
                    Some(ClientCommand::SetInterception(true))
                }
                x if x == pb::Action::DisableInterception as i32 => {
                    Some(ClientCommand::SetInterception(false))
                }
                x if x == pb::Action::EnableFirewall as i32 => {
                    Some(ClientCommand::SetFirewall(true))
                }
                x if x == pb::Action::DisableFirewall as i32 => {
                    Some(ClientCommand::SetFirewall(false))
                }
                x if x == pb::Action::ReloadFwRules as i32 => {
                    Some(ClientCommand::ReloadFirewall)
                }
                x if x == pb::Action::ChangeConfig as i32 => {
                    Some(ClientCommand::ApplyConfig(notification.data.clone()))
                }
                x if x == pb::Action::EnableRule as i32 => {
                    Some(ClientCommand::UpsertRules(notification.rules.clone()))
                }
                x if x == pb::Action::DisableRule as i32 => {
                    Some(ClientCommand::UpsertRules(notification.rules.clone()))
                }
                x if x == pb::Action::DeleteRule as i32 => {
                    Some(ClientCommand::DeleteRules(
                        notification.rules.iter().map(|rule| rule.name.clone()).collect(),
                    ))
                }
                x if x == pb::Action::ChangeRule as i32 => {
                    Some(ClientCommand::UpsertRules(notification.rules.clone()))
                }
                x if x == pb::Action::Stop as i32 => {
                    Some(ClientCommand::Shutdown)
                }
                _ => None,
            };

            if let Some(cmd) = cmd {
                let _ = self.bus.client_cmd_tx.send(cmd).await;
            }

            let _ = reply_tx
                .send(pb::NotificationReply {
                    id: notification.id,
                    code: pb::NotificationReplyCode::Ok as i32,
                    data: String::new(),
                })
                .await;
        }

        Ok(())
    }
}

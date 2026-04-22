use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::{
    bus::Bus,
    client::{client::Client, notifications::NotificationStream},
    models::{command_rpc::ClientCommand, command_rpc::IncomingTaskNotification},
    services::config_service::ConfigService,
};

#[derive(Clone)]
pub struct NotificationFlow {
    bus: Bus,
    config: ConfigService,
}

impl NotificationFlow {
    pub fn new(bus: Bus, config: ConfigService) -> Self {
        Self { bus, config }
    }

    pub async fn run(self, mut task_reply_rx: mpsc::Receiver<pb::NotificationReply>) -> Result<()> {
        loop {
            let client_addr = self.config.snapshot().await.client_addr;

            let mut client = match Client::connect(&client_addr).await {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!("notification flow connect failed: {err}");
                    if task_reply_rx.is_closed() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let stream = match NotificationStream::open(&mut client).await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::warn!("notification stream open failed: {err}");
                    if task_reply_rx.is_closed() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let mut inbound = stream.inbound;
            let reply_tx = stream.reply_tx;

            if reply_tx.send(notification_hello_reply()).await.is_err() {
                tracing::warn!("notification hello send failed; reconnecting");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            let stop_runtime_tasks = loop {
                tokio::select! {
                    maybe_reply = task_reply_rx.recv() => {
                        match maybe_reply {
                            Some(reply) => {
                                if reply_tx.send(reply).await.is_err() {
                                    tracing::warn!("notification reply stream closed; reconnecting");
                                    break true;
                                }
                            }
                            None => return Ok(()),
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        let updated_addr = self.config.snapshot().await.client_addr;
                        if updated_addr != client_addr {
                            tracing::info!(old_addr = %client_addr, new_addr = %updated_addr, "notification endpoint changed; reconnecting");
                            break true;
                        }
                    }
                    incoming = inbound.message() => {
                        match incoming {
                            Ok(Some(notification)) => {
                                if is_stream_close_notification(notification.r#type) {
                                    tracing::info!(
                                        action = notification.r#type,
                                        "notification stream close requested by server"
                                    );
                                    break true;
                                }

                                let cmd = match notification.r#type {
                                    x if x == pb::Action::EnableInterception as i32 => {
                                        Some(ClientCommand::SetInterception {
                                            notification_id: notification.id,
                                            enabled: true,
                                        })
                                    }
                                    x if x == pb::Action::DisableInterception as i32 => {
                                        Some(ClientCommand::SetInterception {
                                            notification_id: notification.id,
                                            enabled: false,
                                        })
                                    }
                                    x if x == pb::Action::EnableFirewall as i32 => {
                                        Some(ClientCommand::SetFirewall {
                                            notification_id: notification.id,
                                            enabled: true,
                                        })
                                    }
                                    x if x == pb::Action::DisableFirewall as i32 => {
                                        Some(ClientCommand::SetFirewall {
                                            notification_id: notification.id,
                                            enabled: false,
                                        })
                                    }
                                    x if x == pb::Action::ReloadFwRules as i32 => {
                                        Some(ClientCommand::ReloadFirewall {
                                            notification_id: notification.id,
                                            sys_firewall: notification.sys_firewall.clone(),
                                        })
                                    }
                                    x if x == pb::Action::ChangeConfig as i32 => {
                                        Some(ClientCommand::ApplyConfig {
                                            notification_id: notification.id,
                                            raw_json: notification.data.clone(),
                                        })
                                    }
                                    x if x == pb::Action::EnableRule as i32 => {
                                        Some(ClientCommand::EnableRules {
                                            notification_id: notification.id,
                                            rules: notification.rules.clone(),
                                        })
                                    }
                                    x if x == pb::Action::DisableRule as i32 => {
                                        Some(ClientCommand::DisableRules {
                                            notification_id: notification.id,
                                            rules: notification.rules.clone(),
                                        })
                                    }
                                    x if x == pb::Action::DeleteRule as i32 => {
                                        Some(ClientCommand::DeleteRules {
                                            notification_id: notification.id,
                                            rule_names: notification
                                                .rules
                                                .iter()
                                                .map(|rule| rule.name.clone())
                                                .collect(),
                                        })
                                    }
                                    x if x == pb::Action::ChangeRule as i32 => {
                                        Some(ClientCommand::UpsertRules {
                                            notification_id: notification.id,
                                            rules: notification.rules.clone(),
                                        })
                                    }
                                    x if x == pb::Action::TaskStart as i32 => {
                                        parse_task_notification(&notification).map(ClientCommand::StartTask)
                                    }
                                    x if x == pb::Action::TaskStop as i32 => {
                                        parse_task_notification(&notification).map(ClientCommand::StopTask)
                                    }
                                    x if x == pb::Action::LogLevel as i32 => {
                                        parse_log_level_notification(&notification).map(|level| {
                                            ClientCommand::SetLogLevel {
                                                notification_id: notification.id,
                                                level,
                                            }
                                        })
                                    }
                                    x if x == pb::Action::Stop as i32 => {
                                        Some(ClientCommand::Shutdown {
                                            notification_id: notification.id,
                                        })
                                    }
                                    _ => None,
                                };

                                if let Some(cmd) = cmd {
                                    if self.bus.client_cmd_tx.send(cmd).await.is_err() {
                                        let _ = reply_tx
                                            .send(pb::NotificationReply {
                                                id: notification.id,
                                                code: pb::NotificationReplyCode::Error as i32,
                                                data: "failed to queue command".to_string(),
                                            })
                                            .await;
                                    }
                                } else if notification.r#type == pb::Action::TaskStart as i32
                                    || notification.r#type == pb::Action::TaskStop as i32
                                {
                                    let _ = reply_tx
                                        .send(pb::NotificationReply {
                                            id: notification.id,
                                            code: pb::NotificationReplyCode::Error as i32,
                                            data: "invalid task payload".to_string(),
                                        })
                                        .await;
                                } else if notification.r#type == pb::Action::LogLevel as i32 {
                                    let _ = reply_tx
                                        .send(pb::NotificationReply {
                                            id: notification.id,
                                            code: pb::NotificationReplyCode::Error as i32,
                                            data: "invalid log level payload".to_string(),
                                        })
                                        .await;
                                } else {
                                    let _ = reply_tx
                                        .send(pb::NotificationReply {
                                            id: notification.id,
                                            code: pb::NotificationReplyCode::Error as i32,
                                            data: "unsupported notification action".to_string(),
                                        })
                                        .await;
                                }
                            }
                            Ok(None) => {
                                tracing::warn!("notification stream closed by remote peer; reconnecting");
                                break true;
                            }
                            Err(err) => {
                                tracing::warn!("notification stream receive failed: {err}");
                                break true;
                            }
                        }
                    }
                }
            };

            if stop_runtime_tasks {
                if self
                    .bus
                    .client_cmd_tx
                    .send(ClientCommand::StopRuntimeTasks)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        "failed to queue temporary task teardown after notification disconnect"
                    );
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }
}

fn parse_task_notification(
    notification: &pb::Notification,
) -> Option<crate::models::command_rpc::TaskNotification> {
    let task = serde_json::from_str::<IncomingTaskNotification>(&notification.data).ok()?;
    Some(crate::models::command_rpc::TaskNotification {
        notification_id: notification.id,
        name: task.name,
        data: task.data,
    })
}

fn parse_log_level_notification(notification: &pb::Notification) -> Option<i32> {
    let raw = notification.data.trim();
    if raw.is_empty() {
        return None;
    }

    if let Ok(value) = raw.parse::<i32>() {
        return Some(value);
    }

    let parsed = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    match parsed {
        serde_json::Value::Number(n) => n.as_i64().and_then(|v| i32::try_from(v).ok()),
        serde_json::Value::Object(obj) => {
            let candidate = obj.get("log_level").or_else(|| obj.get("level"))?;
            match candidate {
                serde_json::Value::Number(n) => n.as_i64().and_then(|v| i32::try_from(v).ok()),
                serde_json::Value::String(s) => s.parse::<i32>().ok(),
                _ => None,
            }
        }
        _ => None,
    }
}

fn notification_hello_reply() -> pb::NotificationReply {
    pb::NotificationReply {
        id: 0,
        code: pb::NotificationReplyCode::Ok as i32,
        data: String::new(),
    }
}

fn is_stream_close_notification(action: i32) -> bool {
    action <= pb::Action::None as i32
}

#[cfg(test)]
mod tests {
    use opensnitch_proto::pb;

    use super::{
        is_stream_close_notification, notification_hello_reply, parse_log_level_notification,
        parse_task_notification,
    };

    #[test]
    fn parse_task_notification_accepts_valid_payload() {
        let notification = pb::Notification {
            id: 10,
            data: r#"{"Name":"pid-monitor","Data":{"pid":1234}}"#.to_string(),
            ..Default::default()
        };

        let parsed = parse_task_notification(&notification).expect("task payload");
        assert_eq!(parsed.notification_id, 10);
        assert_eq!(parsed.name, "pid-monitor");
    }

    #[test]
    fn parse_log_level_notification_supports_number_and_object() {
        let number = pb::Notification {
            data: "3".to_string(),
            ..Default::default()
        };
        assert_eq!(parse_log_level_notification(&number), Some(3));

        let object = pb::Notification {
            data: r#"{"log_level":7}"#.to_string(),
            ..Default::default()
        };
        assert_eq!(parse_log_level_notification(&object), Some(7));
    }

    #[test]
    fn notification_hello_reply_matches_go_stream_handshake() {
        let reply = notification_hello_reply();
        assert_eq!(reply.id, 0);
        assert_eq!(reply.code, pb::NotificationReplyCode::Ok as i32);
        assert!(reply.data.is_empty());
    }

    #[test]
    fn stream_close_notification_recognizes_action_none_and_lower_values() {
        assert!(is_stream_close_notification(pb::Action::None as i32));
        assert!(is_stream_close_notification(-1));
        assert!(!is_stream_close_notification(
            pb::Action::EnableInterception as i32
        ));
    }
}

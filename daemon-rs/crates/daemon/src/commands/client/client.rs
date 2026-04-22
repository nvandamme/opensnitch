use opensnitch_proto::pb;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::{
    models::{
        command_action::CommandAction,
        command_rpc::{ClientCommand, IncomingTaskNotification, TaskNotification},
        firewall_config::FirewallConfig,
        rule_record::RuleRecord,
    },
    utils::{json_value::object_get_case_insensitive, notification_reply::send_notification_reply},
};

const CLIENT_COMMAND_NOTIFICATION_LABEL: &str = "client command notification";

pub(crate) enum NotificationCommandDecision {
    Command(ClientCommand),
    InvalidLogLevel,
    None,
}

pub(crate) async fn command_from_action_or_reply(
    notification_id: u64,
    action: CommandAction,
    data: &str,
    rules: Vec<RuleRecord>,
    firewall: Option<FirewallConfig>,
    reply_tx: &mpsc::Sender<pb::NotificationReply>,
) -> NotificationCommandDecision {
    if let Some(toggle_cmd) = parse_toggle_command(notification_id, action) {
        return NotificationCommandDecision::Command(toggle_cmd);
    }

    match action {
        CommandAction::ReloadFwRules => {
            NotificationCommandDecision::Command(ClientCommand::ReloadFirewall {
                notification_id,
                firewall,
            })
        }
        CommandAction::ChangeConfig => {
            NotificationCommandDecision::Command(ClientCommand::ApplyConfig {
                notification_id,
                raw_json: data.to_string(),
            })
        }
        CommandAction::EnableRule => {
            NotificationCommandDecision::Command(ClientCommand::EnableRules {
                notification_id,
                rules,
            })
        }
        CommandAction::DisableRule => {
            NotificationCommandDecision::Command(ClientCommand::DisableRules {
                notification_id,
                rules,
            })
        }
        CommandAction::DeleteRule => {
            NotificationCommandDecision::Command(ClientCommand::DeleteRules {
                notification_id,
                rule_names: rules.into_iter().map(|rule| rule.name).collect(),
            })
        }
        CommandAction::ChangeRule => {
            NotificationCommandDecision::Command(ClientCommand::UpsertRules {
                notification_id,
                rules,
            })
        }
        CommandAction::TaskStart => {
            if let Some(cmd) =
                parse_task_command_or_reply(notification_id, data, reply_tx, true).await
            {
                NotificationCommandDecision::Command(cmd)
            } else {
                NotificationCommandDecision::None
            }
        }
        CommandAction::TaskStop => {
            if let Some(cmd) =
                parse_task_command_or_reply(notification_id, data, reply_tx, false).await
            {
                NotificationCommandDecision::Command(cmd)
            } else {
                NotificationCommandDecision::None
            }
        }
        CommandAction::LogLevel => parse_log_level_data(data)
            .map(|level| {
                NotificationCommandDecision::Command(ClientCommand::SetLogLevel {
                    notification_id,
                    level,
                })
            })
            .unwrap_or(NotificationCommandDecision::InvalidLogLevel),
        CommandAction::Stop => {
            NotificationCommandDecision::Command(ClientCommand::Shutdown { notification_id })
        }
        CommandAction::EnableInterception
        | CommandAction::DisableInterception
        | CommandAction::EnableFirewall
        | CommandAction::DisableFirewall => NotificationCommandDecision::None,
        CommandAction::None => NotificationCommandDecision::None,
    }
}

async fn parse_task_command_or_reply(
    id: u64,
    data: &str,
    reply_tx: &mpsc::Sender<pb::NotificationReply>,
    start: bool,
) -> Option<ClientCommand> {
    match parse_task_notification_data(id, data) {
        Ok(task) => {
            if start {
                Some(ClientCommand::StartTask(task))
            } else {
                Some(ClientCommand::StopTask(task))
            }
        }
        Err(err) => {
            if start {
                tracing::warn!(notification_id = id, "invalid task-start payload: {err}");
            } else {
                tracing::warn!(
                    notification_id = id,
                    "invalid task-stop payload in notification"
                );
            }

            let data = if start {
                err
            } else {
                format!("Error stopping task: {data}")
            };
            let _ = send_notification_reply(
                reply_tx,
                id,
                pb::NotificationReplyCode::Error,
                data,
                CLIENT_COMMAND_NOTIFICATION_LABEL,
            )
            .await;
            None
        }
    }
}

fn parse_toggle_command(notification_id: u64, action: CommandAction) -> Option<ClientCommand> {
    match action {
        CommandAction::EnableInterception => Some(ClientCommand::SetInterception {
            notification_id,
            enabled: true,
        }),
        CommandAction::DisableInterception => Some(ClientCommand::SetInterception {
            notification_id,
            enabled: false,
        }),
        CommandAction::EnableFirewall => Some(ClientCommand::SetFirewall {
            notification_id,
            enabled: true,
        }),
        CommandAction::DisableFirewall => Some(ClientCommand::SetFirewall {
            notification_id,
            enabled: false,
        }),
        _ => None,
    }
}

pub(crate) fn parse_task_notification_data(
    notification_id: u64,
    raw_data: &str,
) -> Result<TaskNotification, String> {
    let task = serde_json::from_str::<IncomingTaskNotification>(raw_data)
        .map_err(|err| err.to_string())?;
    Ok(TaskNotification {
        notification_id,
        name: task.name,
        data: task.data,
    })
}

pub(crate) fn parse_log_level_data(raw_data: &str) -> Option<i32> {
    let raw = raw_data.trim();
    if raw.is_empty() {
        return None;
    }

    if let Ok(value) = raw.parse::<i32>() {
        return Some(value);
    }

    let parsed = serde_json::from_str::<Value>(raw).ok()?;
    match parsed {
        Value::Number(n) => n.as_i64().and_then(|v| i32::try_from(v).ok()),
        Value::Object(obj) => {
            let candidate = object_get_case_insensitive(&obj, &["log_level", "level"])?;
            match candidate {
                Value::Number(n) => n.as_i64().and_then(|v| i32::try_from(v).ok()),
                Value::String(s) => s.parse::<i32>().ok(),
                _ => None,
            }
        }
        _ => None,
    }
}

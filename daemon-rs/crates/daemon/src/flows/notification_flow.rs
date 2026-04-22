use std::collections::VecDeque;

use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::{
    bus::Bus,
    client::{client::Client, notifications::NotificationStream},
    config::Config,
    models::{
        command_rpc::ClientCommand,
        command_rpc::IncomingTaskNotification,
        ui_alert::{UiAlert, UiAlertData, drain_overflow_alerts, enqueue_alert},
    },
    services::{
        config_service::ConfigService, firewall_service::FirewallService,
        rule_service::RuleService, ui_session_service::UiSessionService,
    },
};

#[derive(Clone)]
pub struct NotificationFlow {
    bus: Bus,
    config: ConfigService,
    ui_session: UiSessionService,
    rules: RuleService,
    firewall: FirewallService,
}

impl NotificationFlow {
    pub fn new(
        bus: Bus,
        config: ConfigService,
        ui_session: UiSessionService,
        rules: RuleService,
        firewall: FirewallService,
    ) -> Self {
        Self {
            bus,
            config,
            ui_session,
            rules,
            firewall,
        }
    }

    pub async fn run(
        self,
        mut task_reply_rx: mpsc::Receiver<pb::NotificationReply>,
        mut alert_rx: mpsc::Receiver<UiAlert>,
    ) -> Result<()> {
        const QUEUED_ALERTS_MAX: usize = 32;
        let mut queued_alerts: VecDeque<UiAlert> = VecDeque::with_capacity(QUEUED_ALERTS_MAX);

        let queue_alert = |queue: &mut VecDeque<UiAlert>, alert: UiAlert| {
            if queue.len() >= QUEUED_ALERTS_MAX
                && let Some(discarded) = queue.pop_front()
            {
                tracing::debug!(discarded = ?discarded, pending = queue.len(), "discarding oldest queued alert");
            }
            queue.push_back(alert);
        };

        let drain_alert_overflow = |queue: &mut VecDeque<UiAlert>| {
            for alert in drain_overflow_alerts() {
                queue_alert(queue, alert);
            }
        };

        loop {
            drain_alert_overflow(&mut queued_alerts);
            let config_snapshot = self.config.snapshot().await;
            let client_addr = config_snapshot.client_addr.clone();
            let auth_mode = config_snapshot.client_auth.auth_type.as_name();
            let current_auth_fingerprint = auth_fingerprint(&config_snapshot);
            tracing::info!(addr = %client_addr, "notification flow: connecting to UI endpoint");

            let mut client = match Client::connect_with_config(&config_snapshot).await {
                Ok(client) => client,
                Err(err) => {
                    self.ui_session.set_connected(false);
                    tracing::warn!("notification flow connect failed: {err}");
                    enqueue_alert(
                        &self.bus.alert_tx,
                        UiAlert::warning(format!("notification flow connect failed: {err}")),
                    );
                    if task_reply_rx.is_closed() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let rules = self.rules.list_proto().await;
            let firewall_state = self.firewall.snapshot().await;
            let system_firewall = self.firewall.system_firewall().await;
            let subscribe_cfg = client.build_subscribe_config(
                &config_snapshot,
                rules,
                firewall_state.enabled,
                system_firewall,
            );

            match client.subscribe(subscribe_cfg).await {
                Ok(subscribe_reply) => {
                    if let Some(action) = parse_connected_default_action(&subscribe_reply.config) {
                        self.ui_session.set_connected_default_action(action).await;
                    }
                }
                Err(err) => {
                    self.ui_session.set_connected(false);
                    tracing::warn!("notification subscribe failed: {err}");
                    enqueue_alert(
                        &self.bus.alert_tx,
                        UiAlert::warning(format!("notification subscribe failed: {err}")),
                    );
                    if task_reply_rx.is_closed() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }

            let poller_addr = client_addr
                .strip_prefix("unix:")
                .or_else(|| client_addr.strip_prefix("unix-abstract:"))
                .unwrap_or(client_addr.as_str());
            tracing::debug!("UI service poller started for socket {poller_addr}");

            let stream = match NotificationStream::open(&mut client).await {
                Ok(stream) => stream,
                Err(err) => {
                    self.ui_session.set_connected(false);
                    tracing::warn!("notification stream open failed: {err}");
                    enqueue_alert(
                        &self.bus.alert_tx,
                        UiAlert::warning(format!("notification stream open failed: {err}")),
                    );
                    if task_reply_rx.is_closed() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let mut inbound = stream.inbound;
            let reply_tx = stream.reply_tx;
            tracing::debug!("UI auth: {auth_mode}");

            if reply_tx.send(notification_hello_reply()).await.is_err() {
                self.ui_session.set_connected(false);
                tracing::warn!("notification hello send failed; reconnecting");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            self.ui_session.set_connected(true);
            tracing::info!("notification flow: hello handshake sent");
            if self
                .bus
                .client_cmd_tx
                .send(ClientCommand::ResumeRuntimeTasks)
                .await
                .is_err()
            {
                tracing::warn!("failed to queue runtime task resume command after UI handshake");
            }

            while let Some(alert) = queued_alerts.pop_front() {
                let pb_alert = build_alert(alert.clone());
                if let Err(err) = client.post_alert(pb_alert).await {
                    queue_alert(&mut queued_alerts, alert);
                    tracing::warn!("failed to flush queued alert to UI endpoint: {err}");
                    break;
                }
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
                            None => {
                                self.ui_session.set_connected(false);
                                tracing::info!("uiClient exit");
                                return Ok(());
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        drain_alert_overflow(&mut queued_alerts);
                        let updated = self.config.snapshot().await;
                        let updated_addr = updated.client_addr.clone();
                        if updated_addr != client_addr {
                            tracing::info!(old_addr = %client_addr, new_addr = %updated_addr, "notification endpoint changed; reconnecting");
                            break true;
                        }
                        let updated_auth = auth_fingerprint(&updated);
                        if updated_auth != current_auth_fingerprint {
                            tracing::info!("notification auth settings changed; reconnecting");
                            break true;
                        }
                    }
                    maybe_alert = alert_rx.recv() => {
                        match maybe_alert {
                            Some(alert) => {
                                let pb_alert = build_alert(alert.clone());
                                if let Err(err) = client.post_alert(pb_alert).await {
                                    queue_alert(&mut queued_alerts, alert);
                                    tracing::warn!("failed to post alert to UI endpoint: {err}");
                                    break true;
                                }
                            }
                            None => {
                                tracing::debug!("alert queue channel closed");
                            }
                        }
                    }
                    incoming = inbound.message() => {
                        match incoming {
                            Ok(Some(notification)) => {
                                tracing::info!(
                                    notification_id = notification.id,
                                    action = notification.r#type,
                                    "notification received"
                                );
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
                                        match parse_task_notification(&notification) {
                                            Ok(task) => Some(ClientCommand::StartTask(task)),
                                            Err(err) => {
                                                tracing::warn!(notification_id = notification.id, "invalid task-start payload: {err}");
                                                let _ = reply_tx
                                                    .send(pb::NotificationReply {
                                                        id: notification.id,
                                                        code: pb::NotificationReplyCode::Error as i32,
                                                        data: err,
                                                    })
                                                    .await;
                                                None
                                            }
                                        }
                                    }
                                    x if x == pb::Action::TaskStop as i32 => {
                                        match parse_task_notification(&notification) {
                                            Ok(task) => Some(ClientCommand::StopTask(task)),
                                            Err(_) => {
                                                tracing::warn!(notification_id = notification.id, "invalid task-stop payload in notification");
                                                let _ = reply_tx
                                                    .send(pb::NotificationReply {
                                                        id: notification.id,
                                                        code: pb::NotificationReplyCode::Error as i32,
                                                        data: format!("Error stopping task: {}", notification.data),
                                                    })
                                                    .await;
                                                None
                                            }
                                        }
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
                                    tracing::debug!(notification_id = notification.id, action = notification.r#type, "queueing notification command");
                                    if self.bus.client_cmd_tx.send(cmd).await.is_err() {
                                        let _ = reply_tx
                                            .send(pb::NotificationReply {
                                                id: notification.id,
                                                code: pb::NotificationReplyCode::Error as i32,
                                                data: "failed to queue command".to_string(),
                                            })
                                            .await;
                                        tracing::error!(notification_id = notification.id, "failed to queue notification command");
                                    }
                                } else if notification.r#type == pb::Action::LogLevel as i32 {
                                    tracing::warn!(notification_id = notification.id, "invalid log-level payload in notification");
                                    let _ = reply_tx
                                        .send(pb::NotificationReply {
                                            id: notification.id,
                                            code: pb::NotificationReplyCode::Error as i32,
                                            data: "invalid log level payload".to_string(),
                                        })
                                        .await;
                                } else {
                                    tracing::debug!(notification_id = notification.id, action = notification.r#type, "unsupported notification action ignored");
                                    enqueue_alert(&self.bus.alert_tx, UiAlert::warning(format!(
                                        "unsupported notification action ignored: {}",
                                        notification.r#type
                                    )));
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
                self.ui_session.set_connected(false);
                tracing::info!("notification flow: requesting temporary runtime task teardown");
                if self
                    .bus
                    .client_cmd_tx
                    .send(ClientCommand::PauseRuntimeTasks)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        "failed to queue temporary task pause command after notification disconnect"
                    );
                }
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

            tracing::debug!("client.disconnect()");

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        self.ui_session.set_connected(false);
        tracing::info!("uiClient exit");
        Ok(())
    }
}

fn auth_fingerprint(config: &Config) -> String {
    let tls = &config.client_auth.tls_options;
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        config.client_auth.auth_type.as_name(),
        tls.ca_cert,
        tls.server_cert,
        tls.client_cert,
        tls.client_key,
        tls.client_auth_type,
        tls.skip_verify,
    )
}

fn parse_connected_default_action(raw_config_json: &str) -> Option<crate::config::DefaultAction> {
    let raw = serde_json::from_str::<serde_json::Value>(raw_config_json).ok()?;
    let obj = raw.as_object()?;
    let action = object_get_case_insensitive(obj, &["DefaultAction"])
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    Some(crate::config::DefaultAction::from_name(action))
}

fn build_alert(alert: UiAlert) -> pb::Alert {
    let data = match alert.data {
        UiAlertData::Text(text) => pb::alert::Data::Text(text),
        UiAlertData::Connection(conn) => pb::alert::Data::Conn(conn),
        UiAlertData::Process(proc_info) => pb::alert::Data::Proc(proc_info),
    };

    pb::Alert {
        id: now_nanos(),
        r#type: alert.alert_type,
        action: alert.action,
        priority: alert.priority,
        what: alert.what,
        data: Some(data),
    }
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_nanos() as u64)
        .unwrap_or(0)
}

fn object_get_case_insensitive<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    candidates: &[&str],
) -> Option<&'a serde_json::Value> {
    obj.iter().find_map(|(key, value)| {
        candidates
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
            .then_some(value)
    })
}

pub(crate) fn parse_task_notification(
    notification: &pb::Notification,
) -> Result<crate::models::command_rpc::TaskNotification, String> {
    let task = serde_json::from_str::<IncomingTaskNotification>(&notification.data)
        .map_err(|err| err.to_string())?;
    Ok(crate::models::command_rpc::TaskNotification {
        notification_id: notification.id,
        name: task.name,
        data: task.data,
    })
}

pub(crate) fn parse_log_level_notification(notification: &pb::Notification) -> Option<i32> {
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
            let candidate = object_get_case_insensitive(&obj, &["log_level", "level"])?;
            match candidate {
                serde_json::Value::Number(n) => n.as_i64().and_then(|v| i32::try_from(v).ok()),
                serde_json::Value::String(s) => s.parse::<i32>().ok(),
                _ => None,
            }
        }
        _ => None,
    }
}

pub(crate) fn notification_hello_reply() -> pb::NotificationReply {
    pb::NotificationReply {
        id: 0,
        code: pb::NotificationReplyCode::Ok as i32,
        data: String::new(),
    }
}

pub(crate) fn is_stream_close_notification(action: i32) -> bool {
    action <= pb::Action::None as i32
}

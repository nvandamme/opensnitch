use std::collections::VecDeque;
use std::hash::{Hash, Hasher};

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
        ui_alert::{UiAlert, UiAlertData, drain_overflow_alerts},
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
    const RECONNECT_DELAY: Duration = Duration::from_secs(1);

    async fn send_channel_item<T>(tx: &mpsc::Sender<T>, item: T) -> bool
    where
        T: Send,
    {
        match tx.try_send(item) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => tx.send(item).await.is_ok(),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    async fn reconnect_with_log(
        &self,
        task_reply_rx: &mpsc::Receiver<pb::NotificationReply>,
        warning: &str,
    ) -> bool {
        self.ui_session.set_connected(false);
        tracing::warn!("{warning}");
        if task_reply_rx.is_closed() {
            return true;
        }
        tokio::time::sleep(Self::RECONNECT_DELAY).await;
        false
    }

    async fn reconnect_without_warning(
        &self,
        task_reply_rx: &mpsc::Receiver<pb::NotificationReply>,
    ) -> bool {
        self.ui_session.set_connected(false);
        if task_reply_rx.is_closed() {
            return true;
        }
        tokio::time::sleep(Self::RECONNECT_DELAY).await;
        false
    }

    async fn request_runtime_task_teardown(&self) {
        tracing::info!("notification flow: requesting temporary runtime task teardown");
        if !Self::send_channel_item(&self.bus.client_cmd_tx, ClientCommand::StopRuntimeTasks).await
        {
            tracing::warn!("failed to queue temporary task teardown after notification disconnect");
        }
    }

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
        let mut queued_alerts: VecDeque<pb::Alert> = VecDeque::with_capacity(QUEUED_ALERTS_MAX);

        let queue_alert = |queue: &mut VecDeque<pb::Alert>, alert: pb::Alert| {
            if queue.len() >= QUEUED_ALERTS_MAX
                && let Some(discarded) = queue.pop_front()
            {
                tracing::debug!(discarded = ?discarded, pending = queue.len(), "discarding oldest queued alert");
            }
            queue.push_back(alert);
        };

        let drain_alert_overflow = |queue: &mut VecDeque<pb::Alert>| {
            for alert in drain_overflow_alerts() {
                queue_alert(queue, Self::build_alert(alert));
            }
        };

        loop {
            drain_alert_overflow(&mut queued_alerts);
            let config_snapshot = self.config.snapshot_arc();
            let client_addr = config_snapshot.client_addr.as_str();
            let auth_mode = config_snapshot.client_auth.auth_type.as_name();
            let current_auth_fingerprint = Self::auth_fingerprint(&config_snapshot);
            tracing::info!(addr = %client_addr, "notification flow: connecting to UI endpoint");

            let mut client = match Client::connect_with_config(&config_snapshot).await {
                Ok(client) => client,
                Err(err) => {
                    if self
                        .reconnect_with_log(
                            &task_reply_rx,
                            &format!("notification flow connect failed: {err}"),
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
            };

            let rules = self.rules.list_proto_arc().await;
            let firewall_state = self.firewall.snapshot_arc();
            let subscribe_cfg = Client::build_subscribe_config_from_snapshots(
                &config_snapshot,
                &rules,
                firewall_state.state.enabled,
                &firewall_state.system_firewall,
            );

            match client.subscribe(subscribe_cfg).await {
                Ok(subscribe_reply) => {
                    if let Some(action) =
                        Self::parse_connected_default_action(&subscribe_reply.config)
                    {
                        self.ui_session.set_connected_default_action(action);
                    }
                }
                Err(err) => {
                    if self
                        .reconnect_with_log(
                            &task_reply_rx,
                            &format!("notification subscribe failed: {err}"),
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
            }

            let poller_addr = client_addr
                .strip_prefix("unix:")
                .or_else(|| client_addr.strip_prefix("unix-abstract:"))
                .unwrap_or(client_addr);
            tracing::debug!("UI service poller started for socket {poller_addr}");

            let stream = match NotificationStream::open(&mut client).await {
                Ok(stream) => stream,
                Err(err) => {
                    if self
                        .reconnect_with_log(
                            &task_reply_rx,
                            &format!("notification stream open failed: {err}"),
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
            };

            let mut inbound = stream.inbound;
            let reply_tx = stream.reply_tx;
            tracing::debug!("UI auth: {auth_mode}");
            if !Self::send_channel_item(&reply_tx, Self::notification_hello_reply()).await {
                if self.reconnect_without_warning(&task_reply_rx).await {
                    break;
                }
                continue;
            }
            self.ui_session.set_connected(true);
            tracing::info!("notification flow: hello handshake sent");
            if !Self::send_channel_item(&self.bus.client_cmd_tx, ClientCommand::ResumeRuntimeTasks)
                .await
            {
                tracing::warn!("failed to queue runtime task resume command after UI handshake");
            }

            while let Some(alert) = queued_alerts.pop_front() {
                if let Err(err) = client.post_alert(alert.clone()).await {
                    queue_alert(&mut queued_alerts, alert);
                    tracing::warn!("failed to flush queued alert to UI endpoint: {err}");
                    break;
                }
            }

            let mut config_refresh_tick = tokio::time::interval(Duration::from_secs(1));
            let stop_runtime_tasks = loop {
                tokio::select! {
                    maybe_reply = task_reply_rx.recv() => {
                        match maybe_reply {
                            Some(reply) => {
                                if !Self::send_channel_item(&reply_tx, reply).await {
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
                    _ = config_refresh_tick.tick() => {
                        drain_alert_overflow(&mut queued_alerts);
                        let updated = self.config.snapshot_arc();
                        let updated_addr = updated.client_addr.as_str();
                        if updated_addr != client_addr {
                            tracing::info!(old_addr = %client_addr, new_addr = %updated_addr, "notification endpoint changed; reconnecting");
                            break true;
                        }
                        let updated_auth = Self::auth_fingerprint(&updated);
                        if updated_auth != current_auth_fingerprint {
                            tracing::info!("notification auth settings changed; reconnecting");
                            break true;
                        }
                    }
                    maybe_alert = alert_rx.recv() => {
                        match maybe_alert {
                            Some(alert) => {
                                let pb_alert = Self::build_alert(alert);
                                if let Err(err) = client.post_alert(pb_alert.clone()).await {
                                    queue_alert(&mut queued_alerts, pb_alert);
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
                                let pb::Notification {
                                    id,
                                    r#type: action,
                                    data,
                                    rules,
                                    sys_firewall,
                                    ..
                                } = notification;
                                tracing::info!(
                                    notification_id = id,
                                    action,
                                    "notification received"
                                );
                                if Self::is_stream_close_notification(action) {
                                    tracing::info!(
                                        action,
                                        "notification stream close requested by server"
                                    );
                                    break true;
                                }

                                let parsed_action = pb::Action::try_from(action).ok();
                                let cmd = match parsed_action {
                                    Some(pb::Action::EnableInterception) => {
                                        Some(ClientCommand::SetInterception {
                                            notification_id: id,
                                            enabled: true,
                                        })
                                    }
                                    Some(pb::Action::DisableInterception) => {
                                        Some(ClientCommand::SetInterception {
                                            notification_id: id,
                                            enabled: false,
                                        })
                                    }
                                    Some(pb::Action::EnableFirewall) => {
                                        Some(ClientCommand::SetFirewall {
                                            notification_id: id,
                                            enabled: true,
                                        })
                                    }
                                    Some(pb::Action::DisableFirewall) => {
                                        Some(ClientCommand::SetFirewall {
                                            notification_id: id,
                                            enabled: false,
                                        })
                                    }
                                    Some(pb::Action::ReloadFwRules) => {
                                        Some(ClientCommand::ReloadFirewall {
                                            notification_id: id,
                                            sys_firewall,
                                        })
                                    }
                                    Some(pb::Action::ChangeConfig) => {
                                        Some(ClientCommand::ApplyConfig {
                                            notification_id: id,
                                            raw_json: data,
                                        })
                                    }
                                    Some(pb::Action::EnableRule) => {
                                        Some(ClientCommand::EnableRules {
                                            notification_id: id,
                                            rules,
                                        })
                                    }
                                    Some(pb::Action::DisableRule) => {
                                        Some(ClientCommand::DisableRules {
                                            notification_id: id,
                                            rules,
                                        })
                                    }
                                    Some(pb::Action::DeleteRule) => {
                                        Some(ClientCommand::DeleteRules {
                                            notification_id: id,
                                            rule_names: rules.into_iter().map(|rule| rule.name).collect(),
                                        })
                                    }
                                    Some(pb::Action::ChangeRule) => {
                                        Some(ClientCommand::UpsertRules {
                                            notification_id: id,
                                            rules,
                                        })
                                    }
                                    Some(pb::Action::TaskStart) => {
                                        match Self::parse_task_notification_data(id, &data) {
                                            Ok(task) => Some(ClientCommand::StartTask(task)),
                                            Err(err) => {
                                                tracing::warn!(notification_id = id, "invalid task-start payload: {err}");
                                                let _ = Self::send_channel_item(&reply_tx, pb::NotificationReply {
                                                        id,
                                                        code: pb::NotificationReplyCode::Error as i32,
                                                        data: err,
                                                    })
                                                    .await;
                                                None
                                            }
                                        }
                                    }
                                    Some(pb::Action::TaskStop) => {
                                        match Self::parse_task_notification_data(id, &data) {
                                            Ok(task) => Some(ClientCommand::StopTask(task)),
                                            Err(_) => {
                                                tracing::warn!(notification_id = id, "invalid task-stop payload in notification");
                                                let _ = Self::send_channel_item(&reply_tx, pb::NotificationReply {
                                                        id,
                                                        code: pb::NotificationReplyCode::Error as i32,
                                                        data: format!("Error stopping task: {data}"),
                                                    })
                                                    .await;
                                                None
                                            }
                                        }
                                    }
                                    Some(pb::Action::LogLevel) => {
                                        Self::parse_log_level_data(&data).map(|level| {
                                            ClientCommand::SetLogLevel {
                                                notification_id: id,
                                                level,
                                            }
                                        })
                                    }
                                    Some(pb::Action::Stop) => {
                                        Some(ClientCommand::Shutdown {
                                            notification_id: id,
                                        })
                                    }
                                    _ => None,
                                };

                                if let Some(cmd) = cmd {
                                    tracing::debug!(notification_id = id, action, "queueing notification command");
                                    if !Self::send_channel_item(&self.bus.client_cmd_tx, cmd).await {
                                        let _ = Self::send_channel_item(&reply_tx, pb::NotificationReply {
                                                id,
                                                code: pb::NotificationReplyCode::Error as i32,
                                                data: "failed to queue command".to_string(),
                                            })
                                            .await;
                                        tracing::error!(notification_id = id, "failed to queue notification command");
                                    }
                                } else if matches!(parsed_action, Some(pb::Action::LogLevel)) {
                                    tracing::warn!(notification_id = id, "invalid log-level payload in notification");
                                    let _ = Self::send_channel_item(&reply_tx, pb::NotificationReply {
                                            id,
                                            code: pb::NotificationReplyCode::Error as i32,
                                            data: "invalid log level payload".to_string(),
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
                self.ui_session.set_connected(false);
                self.request_runtime_task_teardown().await;
            }

            tracing::debug!("client.disconnect()");

            tokio::time::sleep(Self::RECONNECT_DELAY).await;
        }

        self.ui_session.set_connected(false);
        tracing::info!("uiClient exit");
        Ok(())
    }

    fn auth_fingerprint(config: &Config) -> u64 {
        let tls = &config.client_auth.tls_options;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        config.client_auth.auth_type.as_name().hash(&mut hasher);
        tls.ca_cert.hash(&mut hasher);
        tls.server_cert.hash(&mut hasher);
        tls.server_key.hash(&mut hasher);
        tls.client_cert.hash(&mut hasher);
        tls.client_key.hash(&mut hasher);
        tls.client_auth_type.hash(&mut hasher);
        tls.skip_verify.hash(&mut hasher);
        hasher.finish()
    }

    fn parse_connected_default_action(
        raw_config_json: &str,
    ) -> Option<crate::config::DefaultAction> {
        let raw = serde_json::from_str::<serde_json::Value>(raw_config_json).ok()?;
        let obj = raw.as_object()?;
        let action = Self::object_get_case_insensitive(obj, &["DefaultAction"])
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Some(crate::config::DefaultAction::from_name(action))
    }

    fn build_alert(alert: UiAlert) -> pb::Alert {
        let UiAlert {
            alert_type,
            action,
            priority,
            what,
            data,
        } = alert;

        let data = match data {
            UiAlertData::Text(text) => pb::alert::Data::Text(text),
            UiAlertData::Connection(conn) => pb::alert::Data::Conn(conn),
            UiAlertData::Process(proc_info) => pb::alert::Data::Proc(proc_info),
        };

        pb::Alert {
            id: Self::now_nanos(),
            r#type: alert_type,
            action,
            priority,
            what,
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

    pub(crate) fn parse_task_notification_data(
        notification_id: u64,
        raw_data: &str,
    ) -> Result<crate::models::command_rpc::TaskNotification, String> {
        let task = serde_json::from_str::<IncomingTaskNotification>(raw_data)
            .map_err(|err| err.to_string())?;
        Ok(crate::models::command_rpc::TaskNotification {
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

        let parsed = serde_json::from_str::<serde_json::Value>(raw).ok()?;
        match parsed {
            serde_json::Value::Number(n) => n.as_i64().and_then(|v| i32::try_from(v).ok()),
            serde_json::Value::Object(obj) => {
                let candidate = Self::object_get_case_insensitive(&obj, &["log_level", "level"])?;
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
}

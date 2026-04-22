use std::collections::VecDeque;
use std::hash::{Hash, Hasher};

use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::{
    bus::Bus,
    commands::{
        NotificationCommandDecision, command_from_action_or_reply,
        subscription::SubscriptionCommandService,
    },
    config::Config,
    models::{
        command_rpc::ClientCommand,
        ui_alert::{UiAlert, UiAlertData},
    },
    services::{
        client::{
            Client, NotificationStream, UiSessionService, drain_overflow_alerts,
        },
        config::ConfigService,
        firewall::FirewallService,
        rule::RuleService,
        stats::StatsService,
        subscription::SubscriptionService,
    },
    utils::{
        channel_send::send_with_backpressure,
        notification_reply::build_notification_reply,
        time_nonce::unix_epoch_nanos,
    },
};

#[derive(Clone)]
pub struct NotificationFlow {
    bus: Bus,
    config: ConfigService,
    ui_session: UiSessionService,
    rules: RuleService,
    firewall: FirewallService,
    stats: StatsService,
    subscriptions: SubscriptionService,
}

impl NotificationFlow {
    const RECONNECT_DELAY: Duration = Duration::from_secs(1);

    async fn do_reconnect(
        &self,
        task_reply_rx: &mpsc::Receiver<pb::NotificationReply>,
        warning: Option<&str>,
    ) -> bool {
        self.ui_session.set_connected(false);
        if let Some(msg) = warning {
            tracing::warn!("{msg}");
        }
        if task_reply_rx.is_closed() {
            return true;
        }
        tokio::time::sleep(Self::RECONNECT_DELAY).await;
        false
    }

    async fn request_runtime_task_teardown(&self) {
        tracing::info!("notification flow: requesting temporary runtime task teardown");
        if !send_with_backpressure(&self.bus.client_cmd_tx, ClientCommand::StopRuntimeTasks).await {
            tracing::warn!("failed to queue temporary task teardown after notification disconnect");
        }
    }

    pub fn new(
        bus: Bus,
        config: ConfigService,
        ui_session: UiSessionService,
        rules: RuleService,
        firewall: FirewallService,
        stats: StatsService,
        subscriptions: SubscriptionService,
    ) -> Self {
        Self {
            bus,
            config,
            ui_session,
            rules,
            firewall,
            stats,
            subscriptions,
        }
    }

    pub async fn run(
        self,
        mut task_reply_rx: mpsc::Receiver<pb::NotificationReply>,
        mut alert_rx: mpsc::Receiver<UiAlert>,
    ) -> Result<()> {
        let subscription_command = SubscriptionCommandService::default();
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
            let config_snapshot = self.config.get_snapshot();
            let client_addr = config_snapshot.client_addr.as_str();
            let auth_mode = config_snapshot.client_auth.auth_type.as_name();
            let current_auth_fingerprint = Self::auth_fingerprint(&config_snapshot);
            tracing::info!(addr = %client_addr, "notification flow: connecting to UI endpoint");

            let mut client = match Client::connect_with_config(&config_snapshot).await {
                Ok(client) => client,
                Err(err) => {
                    if self
                        .do_reconnect(
                            &task_reply_rx,
                            Some(&format!("notification flow connect failed: {err}")),
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
            };

            let rules = self.rules.get_proto_snapshot();
            let firewall_state = self.firewall.get_snapshot();
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
                        .do_reconnect(
                            &task_reply_rx,
                            Some(&format!("notification subscribe failed: {err}")),
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
                        .do_reconnect(
                            &task_reply_rx,
                            Some(&format!("notification stream open failed: {err}")),
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
            if !send_with_backpressure(&reply_tx, Self::notification_hello_reply()).await {
                if self.do_reconnect(&task_reply_rx, None).await {
                    break;
                }
                continue;
            }
            self.ui_session.set_connected(true);
            tracing::info!("notification flow: hello handshake sent");
            if !send_with_backpressure(&self.bus.client_cmd_tx, ClientCommand::ResumeRuntimeTasks)
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
                                if !send_with_backpressure(&reply_tx, reply).await {
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
                        let updated = self.config.get_snapshot();
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
                                if matches!(parsed_action, Some(pb::Action::Subscriptions)) {
                                    let reply = subscription_command
                                        .handle_notification_rpc_first(
                                            &mut client,
                                            id,
                                            &data,
                                            &self.subscriptions,
                                            &self.stats,
                                        )
                                        .await;
                                    let _ = send_with_backpressure(&reply_tx, reply).await;
                                    continue;
                                }

                                let cmd = match parsed_action {
                                    Some(action) => {
                                        match command_from_action_or_reply(
                                            id,
                                            action,
                                            &data,
                                            rules,
                                            sys_firewall,
                                            &reply_tx,
                                        )
                                        .await
                                        {
                                            NotificationCommandDecision::Command(cmd) => Some(cmd),
                                            NotificationCommandDecision::InvalidLogLevel => {
                                                tracing::warn!(notification_id = id, "invalid log-level payload in notification");
                                                let _ = send_with_backpressure(
                                                    &reply_tx,
                                                    build_notification_reply(
                                                        id,
                                                        pb::NotificationReplyCode::Error,
                                                        "invalid log level payload",
                                                    ),
                                                )
                                                .await;
                                                None
                                            }
                                            NotificationCommandDecision::None => None,
                                        }
                                    }
                                    None => None,
                                };

                                if let Some(cmd) = cmd {
                                    tracing::debug!(notification_id = id, action, "queueing notification command");
                                    if !send_with_backpressure(&self.bus.client_cmd_tx, cmd).await {
                                        let _ = send_with_backpressure(
                                            &reply_tx,
                                            build_notification_reply(
                                                id,
                                                pb::NotificationReplyCode::Error,
                                                "failed to queue command",
                                            ),
                                        )
                                        .await;
                                        tracing::error!(notification_id = id, "failed to queue notification command");
                                    }
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
        crate::config::DefaultAction::from_raw_config_json(raw_config_json)
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
            id: u64::try_from(unix_epoch_nanos()).unwrap_or(u64::MAX),
            r#type: alert_type,
            action,
            priority,
            what,
            data: Some(data),
        }
    }

    pub(crate) fn notification_hello_reply() -> pb::NotificationReply {
        build_notification_reply(0, pb::NotificationReplyCode::Ok, String::new())
    }

    pub(crate) fn is_stream_close_notification(action: i32) -> bool {
        action <= pb::Action::None as i32
    }
}

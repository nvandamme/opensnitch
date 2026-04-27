use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use anyhow::Result;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::Duration;
use transport_wire_core::ClientTransportPort;
use transport_wire_core::WireAlert;
use transport_wire_core::{
    WireFwChain, WireFwExpression, WireFwRule, WireFwStatement, WireFwStatementValue,
    WireNotificationReply, WireRule, WireRuleOperator, WireSysFirewall,
};

use crate::{
    bus::Bus,
    commands::{NotificationCommandDecision, command_from_action_or_reply},
    config::{AuthMode, Config, LocalPrincipal},
    models::{
        audit::{
            AuditEvent, AuditEventKind,
            ClientAuthorizationAction as ClientAuthorizationSignalPayload,
        },
        command::rpc::ClientCommand,
        notification::alert::UiAlert,
        rule::record::RuleRecord,
    },
    platform::firewall::config::FirewallConfig,
    services::{
        audit::AuditService,
        client::{
            AlertBuffer, ClientService, NotificationStream, build_wire_alert,
            command_action_from_notification_wire, drain_overflow_alerts,
            is_stream_close_notification_wire, notification_error_reply_wire,
            notification_hello_reply_wire,
        },
        config::ConfigService,
        firewall::FirewallService,
        rule::RuleService,
    },
    utils::channel_send::send_with_backpressure,
    utils::name_parsing::case_folded,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UnixPeerCredentials {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) pid: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotificationAuthorizationClass {
    AlwaysAllowed,
    UserScopedAllowed,
    ElevatedRequired,
    AlwaysDenied,
}

#[derive(Clone)]
pub struct NotificationFlow {
    pub(super) bus: Bus,
    alert_buffer: AlertBuffer,
    config: ConfigService,
    pub(super) client_service: ClientService,
    rules: RuleService,
    firewall: FirewallService,
    audit: AuditService,
}

impl NotificationFlow {
    pub(super) const RECONNECT_DELAY: Duration = Duration::from_secs(1);
    pub(super) const RECONNECT_WARN_THROTTLE: Duration = Duration::from_secs(30);

    pub(super) fn verdict_fallback_log_context(config: &Config) -> (&'static str, &'static str) {
        let tunables = crate::tunables::RuntimeTunables::global();
        (
            tunables.nfqueue_overload_policy.as_str(),
            config.ask_timeout_policy.as_name(),
        )
    }

    pub(crate) fn local_principal_allowlist_matches(
        allowlist: &[LocalPrincipal],
        uid: u32,
        peer_gids: &[u32],
    ) -> bool {
        allowlist
            .iter()
            .any(|principal| principal.uid == uid && peer_gids.contains(&principal.gid))
    }

    pub(crate) fn allowed_group_selector_matches(allowed_gids: &[u32], peer_gids: &[u32]) -> bool {
        !allowed_gids.is_empty()
            && peer_gids
                .iter()
                .any(|peer_gid| allowed_gids.contains(peer_gid))
    }

    pub(crate) fn local_peer_principal_allowed(config: &Config) -> bool {
        if matches!(config.auth_mode, AuthMode::Legacy) {
            return true;
        }

        let client_addr = config.client_addr.as_str();
        if client_addr.starts_with("unix:") || client_addr.starts_with("unix-abstract:") {
            let Some(peer) = Self::try_unix_peer_credentials(client_addr) else {
                return false;
            };
            return Self::unix_principal_allowed(config, peer);
        }
        if client_addr.starts_with("http://") || client_addr.starts_with("https://") {
            return match Self::try_loopback_tcp_listen_socket(client_addr) {
                Some(_) => Self::loopback_tcp_principal_allowed(config, client_addr),
                None => true,
            };
        }
        true
    }

    pub fn new(
        bus: Bus,
        alert_buffer: AlertBuffer,
        config: ConfigService,
        client_service: ClientService,
        rules: RuleService,
        firewall: FirewallService,
        audit: AuditService,
    ) -> Self {
        Self {
            bus,
            alert_buffer,
            config,
            client_service,
            rules,
            firewall,
            audit,
        }
    }

    pub async fn run(
        self,
        mut task_reply_rx: mpsc::Receiver<WireNotificationReply>,
        mut alert_rx: mpsc::Receiver<UiAlert>,
    ) -> Result<()> {
        let mut reconnect_state = ReconnectState::default();
        let mut active_session_id: Option<String> = None;
        const QUEUED_ALERTS_MAX: usize = 32;
        let mut queued_alerts: VecDeque<WireAlert> = VecDeque::with_capacity(QUEUED_ALERTS_MAX);

        let queue_alert = |queue: &mut VecDeque<WireAlert>, alert: WireAlert| {
            if queue.len() >= QUEUED_ALERTS_MAX
                && let Some(discarded) = queue.pop_front()
            {
                tracing::debug!(discarded = ?discarded, pending = queue.len(), "discarding oldest queued alert");
            }
            queue.push_back(alert);
        };

        let drain_alert_overflow = |queue: &mut VecDeque<WireAlert>| {
            for alert in drain_overflow_alerts(&self.alert_buffer) {
                queue_alert(queue, build_wire_alert(alert));
            }
        };

        loop {
            drain_alert_overflow(&mut queued_alerts);
            let config_snapshot = self.config.get_snapshot();
            let client_addr = config_snapshot.client_addr.as_str();
            let (nfqueue_overload_policy, ask_timeout_policy) =
                Self::verdict_fallback_log_context(&config_snapshot);
            if !Self::local_peer_principal_allowed(&config_snapshot) {
                if self
                    .do_reconnect(
                        &task_reply_rx,
                        &mut reconnect_state,
                        &mut active_session_id,
                        "client",
                        "local-peer-principal-check",
                        Some("notification flow connect denied: peer principal not allowed by config"),
                    )
                    .await
                {
                    break;
                }
                continue;
            }
            let auth_mode = config_snapshot.client_auth.auth_type.as_name();
            let preconnect_session_binding =
                Self::session_binding_from_client_addr(client_addr, &config_snapshot);
            let preconnect_client_id = preconnect_session_binding.id.clone();
            let preconnect_client_origin = Self::client_origin(&preconnect_session_binding.owner);

            let current_auth_fingerprint = Self::auth_fingerprint(&config_snapshot);
            tracing::debug!(client_id = preconnect_client_id, client_origin = preconnect_client_origin, addr = %client_addr, "notification flow: connecting to client endpoint");

            let (mut client, server_identity) =
                match ClientService::connect_with_config_and_server_identity(&config_snapshot).await
                {
                    Ok(result) => result,
                    Err(err) => {
                        if self
                            .do_reconnect(
                                &task_reply_rx,
                                &mut reconnect_state,
                                &mut active_session_id,
                                preconnect_client_id.as_str(),
                                preconnect_client_origin.as_str(),
                                Some(&format!("notification flow connect failed: {err}")),
                            )
                            .await
                        {
                            break;
                        }
                        continue;
                    }
                };

            let session_binding = Self::session_binding_from_client_addr_and_server_identity(
                client_addr,
                &config_snapshot,
                server_identity.as_deref(),
            );
            let client_id = session_binding.id.clone();
            let client_origin = Self::client_origin(&session_binding.owner);

            if matches!(
                session_binding.owner,
                crate::services::client::ClientPrincipal::RemoteCert { .. }
            ) {
                tracing::info!(
                    client_id,
                    client_origin,
                    "remote principal binding resolved from live TLS handshake certificate"
                );
                self.audit
                    .emit(AuditEvent::cold(AuditEventKind::ClientAuthorizationAction(
                        ClientAuthorizationSignalPayload::RemotePrincipalResolved {
                            reason: "resolved-from-tls-handshake",
                        },
                    )));
            }

            let rules = self.rules.get_wire_snapshot();
            let firewall_state = self.firewall.get_snapshot();
            let subscribe_cfg = ClientService::build_subscribe_config_from_snapshots(
                &config_snapshot,
                rules.as_ref(),
                firewall_state.state.enabled,
                &firewall_state.system_firewall,
            );

            match ClientTransportPort::subscribe(&mut client, subscribe_cfg).await {
                Ok(subscribe_reply) => {
                    if let Some(action) =
                        Self::parse_connected_default_action(&subscribe_reply.config)
                    {
                        self.client_service.set_connected_default_action(action);
                    }
                }
                Err(err) => {
                    if self
                        .do_reconnect(
                            &task_reply_rx,
                            &mut reconnect_state,
                            &mut active_session_id,
                            client_id.as_str(),
                            client_origin.as_str(),
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
            tracing::debug!(
                client_id,
                client_origin,
                "client service poller started for socket {poller_addr}"
            );

            let stream = match NotificationStream::open(&mut client).await {
                Ok(stream) => stream,
                Err(err) => {
                    if self
                        .do_reconnect(
                            &task_reply_rx,
                            &mut reconnect_state,
                            &mut active_session_id,
                            client_id.as_str(),
                            client_origin.as_str(),
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
            tracing::debug!(client_id, client_origin, "client auth: {auth_mode}");
            if !send_with_backpressure(&reply_tx, notification_hello_reply_wire()).await {
                if self
                    .do_reconnect(
                        &task_reply_rx,
                        &mut reconnect_state,
                        &mut active_session_id,
                        client_id.as_str(),
                        client_origin.as_str(),
                        None,
                    )
                    .await
                {
                    break;
                }
                continue;
            }
            reconnect_state.failures = 0;
            reconnect_state.suppressed_warns = 0;
            reconnect_state.last_warn_at = None;
            reconnect_state.started_at = Instant::now();
            self.connect_owner_bound_session(&session_binding);
            active_session_id = Some(session_binding.id.clone());
            tracing::info!(client_id, client_origin, addr = %client_addr, "notification flow: client connected (hello handshake sent)");
            if !send_with_backpressure(&self.bus.client_cmd_tx, ClientCommand::ResumeRuntimeTasks)
                .await
            {
                tracing::warn!(
                    client_id,
                    client_origin,
                    "failed to queue runtime task resume command after client handshake"
                );
            }

            while let Some(alert) = queued_alerts.pop_front() {
                if let Err(err) = ClientTransportPort::post_alert(&mut client, alert.clone()).await
                {
                    queue_alert(&mut queued_alerts, alert);
                    tracing::warn!(
                        client_id,
                        client_origin,
                        "failed to flush queued alert to client endpoint: {err}"
                    );
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
                                    tracing::warn!(client_id, client_origin, "notification reply stream closed; reconnecting");
                                    break true;
                                }
                            }
                            None => {
                                if let Some(session_id) = active_session_id.take() {
                                    self.client_service.disconnect_session(&session_id);
                                }
                                tracing::info!(client_id, client_origin, "uiClient exit");
                                return Ok(());
                            }
                        }
                    }
                    _ = config_refresh_tick.tick() => {
                        drain_alert_overflow(&mut queued_alerts);
                        let updated = self.config.get_snapshot();
                        let updated_addr = updated.client_addr.as_str();
                        if updated_addr != client_addr {
                            tracing::info!(client_id, client_origin, old_addr = %client_addr, new_addr = %updated_addr, "client stateful disconnect: notification endpoint changed; reconnecting");
                            break true;
                        }
                        let updated_auth = Self::auth_fingerprint(&updated);
                        if updated_auth != current_auth_fingerprint {
                            tracing::info!(client_id, client_origin, "client stateful disconnect: notification auth settings changed; reconnecting");
                            break true;
                        }
                    }
                    maybe_alert = alert_rx.recv() => {
                        match maybe_alert {
                            Some(alert) => {
                                let pb_alert = build_wire_alert(alert);
                                if let Err(err) = ClientTransportPort::post_alert(&mut client, pb_alert.clone()).await {
                                    queue_alert(&mut queued_alerts, pb_alert);
                                    tracing::warn!(client_id, client_origin, "failed to post alert to client endpoint: {err}");
                                    break true;
                                }
                            }
                            None => {
                                tracing::debug!("alert queue channel closed");
                            }
                        }
                    }
                    incoming = inbound.recv() => {
                        match incoming {
                            Ok(Some(notification)) => {
                                let id = notification.id;
                                let action = notification.action;
                                let data = notification.data;
                                let rules = notification.rules;
                                let firewall = notification.sys_firewall;
                                tracing::info!(
                                    client_id,
                                    client_origin,
                                    notification_id = id,
                                    action,
                                    "notification received"
                                );
                                if is_stream_close_notification_wire(action) {
                                    tracing::info!(
                                        client_id,
                                        client_origin,
                                        action,
                                        "client stateful disconnect: notification stream close requested by server"
                                    );
                                    break true;
                                }

                                let parsed_action = command_action_from_notification_wire(action);

                                // Map wire rules to domain models at the adapter boundary.
                                let mut rules: Vec<RuleRecord> = rules
                                    .into_iter()
                                    .map(rule_record_from_wire)
                                    .collect();

                                // Map wire firewall to domain model at the adapter boundary.
                                let mut firewall: Option<FirewallConfig> =
                                    firewall.map(firewall_config_from_wire);

                                match Self::normalize_owner_scoped_rule_mutation_rules(
                                    &config_snapshot,
                                    &session_binding,
                                    parsed_action,
                                    &mut rules,
                                ) {
                                    Ok(injected) if injected > 0 => {
                                        tracing::info!(
                                            client_id,
                                            client_origin,
                                            notification_id = id,
                                            action,
                                            auth_mode = config_snapshot.auth_mode.as_name(),
                                            nfqueue_overload_policy,
                                            ask_timeout_policy,
                                            injected,
                                            "owner-scope constraints injected into rule payload"
                                        );
                                        self.audit.emit(AuditEvent::cold(
                                            AuditEventKind::ClientAuthorizationAction(
                                                ClientAuthorizationSignalPayload::AllowedOwnerScopeRules {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason: "owner-scope-injected",
                                                },
                                            ),
                                        ));
                                    }
                                    Ok(_) => {}
                                    Err(reason) => {
                                        tracing::warn!(
                                            client_id,
                                            client_origin,
                                            notification_id = id,
                                            action,
                                            auth_mode = config_snapshot.auth_mode.as_name(),
                                            nfqueue_overload_policy,
                                            ask_timeout_policy,
                                            reason,
                                            "notification command denied during owner-scope normalization"
                                        );
                                        self.audit.emit(AuditEvent::cold(
                                            AuditEventKind::ClientAuthorizationAction(
                                                ClientAuthorizationSignalPayload::DeniedOwnerScopeRules {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason,
                                                },
                                            ),
                                        ));
                                        let _ = send_with_backpressure(
                                            &reply_tx,
                                            notification_error_reply_wire(id, reason),
                                        )
                                        .await;
                                        continue;
                                    }
                                }

                                match Self::normalize_owner_scoped_firewall_reload(
                                    &config_snapshot,
                                    &session_binding,
                                    parsed_action,
                                    firewall.as_mut(),
                                ) {
                                    Ok(injected) if injected > 0 => {
                                        tracing::info!(
                                            client_id,
                                            client_origin,
                                            notification_id = id,
                                            action,
                                            auth_mode = config_snapshot.auth_mode.as_name(),
                                            nfqueue_overload_policy,
                                            ask_timeout_policy,
                                            injected,
                                            "owner-scope constraints injected into firewall payload"
                                        );
                                        self.audit.emit(AuditEvent::cold(
                                            AuditEventKind::ClientAuthorizationAction(
                                                ClientAuthorizationSignalPayload::AllowedOwnerScopeFirewall {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason: "owner-scope-injected",
                                                },
                                            ),
                                        ));
                                    }
                                    Ok(_) => {}
                                    Err(reason) => {
                                        tracing::warn!(
                                            client_id,
                                            client_origin,
                                            notification_id = id,
                                            action,
                                            auth_mode = config_snapshot.auth_mode.as_name(),
                                            nfqueue_overload_policy,
                                            ask_timeout_policy,
                                            reason,
                                            "notification command denied during firewall owner-scope normalization"
                                        );
                                        self.audit.emit(AuditEvent::cold(
                                            AuditEventKind::ClientAuthorizationAction(
                                                ClientAuthorizationSignalPayload::DeniedOwnerScopeFirewall {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason,
                                                },
                                            ),
                                        ));
                                        let _ = send_with_backpressure(
                                            &reply_tx,
                                            notification_error_reply_wire(id, reason),
                                        )
                                        .await;
                                        continue;
                                    }
                                }

                                if let Err(reason) = Self::notification_command_allowed(
                                    &config_snapshot,
                                    &session_binding,
                                    parsed_action,
                                    &Self::authorization_rule_candidates(
                                        parsed_action,
                                        &rules,
                                        self.rules.get_rule_record_snapshot().as_ref(),
                                    ),
                                    firewall.as_ref(),
                                ) {
                                    tracing::warn!(
                                        client_id,
                                        client_origin,
                                        notification_id = id,
                                        action,
                                        auth_mode = config_snapshot.auth_mode.as_name(),
                                        nfqueue_overload_policy,
                                        ask_timeout_policy,
                                        reason,
                                        "notification command denied by authorization policy"
                                    );
                                    let is_remote_cap_session =
                                        matches!(session_binding.owner, crate::services::client::ClientPrincipal::RemoteCert { .. });
                                    self.audit.emit(AuditEvent::cold(
                                        AuditEventKind::ClientAuthorizationAction(
                                            if is_remote_cap_session {
                                                ClientAuthorizationSignalPayload::DeniedRemoteCapability {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason,
                                                }
                                            } else {
                                                ClientAuthorizationSignalPayload::DeniedAuthorizationPolicy {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason,
                                                }
                                            },
                                        ),
                                    ));
                                    let _ = send_with_backpressure(
                                        &reply_tx,
                                        notification_error_reply_wire(id, reason),
                                    )
                                    .await;
                                    continue;
                                }

                                Self::log_privileged_authorization_allow(
                                    &config_snapshot,
                                    &session_binding,
                                    id,
                                    parsed_action,
                                );
                                if Self::is_privileged_notification_action(parsed_action) {
                                    let is_remote_cap_session =
                                        matches!(session_binding.owner, crate::services::client::ClientPrincipal::RemoteCert { .. });
                                    self.audit.emit(AuditEvent::cold(
                                        AuditEventKind::ClientAuthorizationAction(
                                            if is_remote_cap_session {
                                                ClientAuthorizationSignalPayload::AllowedRemoteCapability {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason: "remote-capability-authorized",
                                                }
                                            } else if matches!(
                                                config_snapshot.auth_mode,
                                                crate::config::AuthMode::Legacy
                                            ) {
                                                ClientAuthorizationSignalPayload::AllowedAuthorizationPolicy {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason: "legacy-compatibility-mode",
                                                }
                                            } else {
                                                ClientAuthorizationSignalPayload::AllowedAuthorizationPolicy {
                                                    notification_id: id,
                                                    action: parsed_action,
                                                    reason: "local-hardened-policy",
                                                }
                                            },
                                        ),
                                    ));
                                }

                                let cmd = match command_from_action_or_reply(
                                            id,
                                            parsed_action,
                                            &data,
                                            rules,
                                            firewall,
                                            &reply_tx,
                                        )
                                        .await
                                        {
                                            NotificationCommandDecision::Command(cmd) => Some(cmd),
                                            NotificationCommandDecision::InvalidLogLevel => {
                                                tracing::warn!(client_id, client_origin, notification_id = id, "invalid log-level payload in notification");
                                                let _ = send_with_backpressure(
                                                    &reply_tx,
                                                    notification_error_reply_wire(
                                                        id,
                                                        "invalid log level payload",
                                                    ),
                                                )
                                                .await;
                                                None
                                            }
                                            NotificationCommandDecision::None => None,
                                        };

                                if let Some(cmd) = cmd {
                                    tracing::debug!(client_id, client_origin, notification_id = id, action, "queueing notification command");
                                    if !send_with_backpressure(&self.bus.client_cmd_tx, cmd).await {
                                        let _ = send_with_backpressure(
                                            &reply_tx,
                                            notification_error_reply_wire(
                                                id,
                                                "failed to queue command",
                                            ),
                                        )
                                        .await;
                                        tracing::error!(client_id, client_origin, notification_id = id, "failed to queue notification command");
                                    }
                                }
                            }
                            Ok(None) => {
                                tracing::warn!(client_id, client_origin, "notification stream closed by remote peer; reconnecting");
                                break true;
                            }
                            Err(err) => {
                                tracing::warn!(client_id, client_origin, "notification stream receive failed: {err}");
                                break true;
                            }
                        }
                    }
                }
            };

            if stop_runtime_tasks {
                if let Some(session_id) = active_session_id.take() {
                    self.client_service.disconnect_session(&session_id);
                }
                self.request_runtime_task_teardown(client_id.as_str(), client_origin.as_str())
                    .await;
            }

            tracing::debug!(client_id, client_origin, "client.disconnect()");

            tokio::time::sleep(Self::RECONNECT_DELAY).await;
        }

        if let Some(session_id) = active_session_id.take() {
            self.client_service.disconnect_session(&session_id);
        }
        let final_cfg = self.config.get_snapshot();
        let final_session =
            Self::session_binding_from_client_addr(final_cfg.client_addr.as_str(), &final_cfg);
        let final_client_origin = Self::client_origin(&final_session.owner);
        tracing::info!(client_id = %final_session.id, client_origin = %final_client_origin, "uiClient exit");
        Ok(())
    }

    fn auth_fingerprint(config: &Config) -> u64 {
        let tls = &config.client_auth.tls_options;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        config.client_auth.auth_type.as_name().hash(&mut hasher);
        config.auth_mode.as_name().hash(&mut hasher);
        tls.ca_cert.hash(&mut hasher);
        tls.server_cert.hash(&mut hasher);
        tls.server_key.hash(&mut hasher);
        tls.client_cert.hash(&mut hasher);
        tls.client_key.hash(&mut hasher);
        tls.client_auth_type.hash(&mut hasher);
        tls.skip_verify.hash(&mut hasher);
        config.local_control_allowed_principals.hash(&mut hasher);
        config.local_control_allowed_group_gids.hash(&mut hasher);
        config.remote_principal_bindings.hash(&mut hasher);
        hasher.finish()
    }

    fn parse_connected_default_action(
        raw_config_json: &str,
    ) -> Option<crate::config::DefaultAction> {
        crate::config::DefaultAction::from_raw_config_json(raw_config_json)
    }

    #[cfg(test)]
    pub(crate) fn is_stream_close_notification(action: i32) -> bool {
        is_stream_close_notification_wire(action)
    }

    #[cfg(test)]
    pub(crate) fn notification_hello_reply() -> transport_wire_core::WireNotificationReply {
        notification_hello_reply_wire()
    }
}

fn rule_record_from_wire(rule: WireRule) -> RuleRecord {
    RuleRecord {
        created_at: OffsetDateTime::from_unix_timestamp(rule.created).ok(),
        updated_at: None,
        name: rule.name,
        description: rule.description,
        action: crate::models::rule::record::RuleAction::from_name(&rule.action),
        duration: crate::models::rule::record::RuleDuration::from_name(&rule.duration),
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        operator: rule_operator_from_wire(rule.operator),
    }
}

fn rule_operator_from_wire(
    operator: Option<WireRuleOperator>,
) -> crate::models::rule::record::RuleOperator {
    let Some(operator) = operator else {
        return crate::models::rule::record::RuleOperator::default();
    };

    let mut parsed = crate::models::rule::record::RuleOperator {
        type_name: operator.type_name,
        operand: operator.operand,
        data: operator.data,
        sensitive: operator.sensitive,
        scope: None,
        list: operator
            .list
            .into_iter()
            .map(|item| rule_operator_from_wire(Some(item)))
            .collect(),
    };

    if case_folded(&parsed.type_name) == "list" {
        parsed.data.clear()
    }

    parsed
}

fn firewall_config_from_wire(value: WireSysFirewall) -> FirewallConfig {
    FirewallConfig {
        enabled: value.enabled,
        version: value.version,
        rules: value
            .rules
            .into_iter()
            .map(firewall_rule_from_wire)
            .collect(),
        chains: value
            .chains
            .into_iter()
            .map(firewall_chain_from_wire)
            .collect(),
        zones: Vec::new(),
    }
}

fn firewall_chain_from_wire(
    value: WireFwChain,
) -> crate::platform::firewall::config::FirewallChain {
    crate::platform::firewall::config::FirewallChain {
        name: value.name,
        table: value.table,
        family: value.family,
        priority: value.priority,
        r#type: value.type_name,
        hook: value.hook,
        policy: value.policy,
        rules: value
            .rules
            .into_iter()
            .map(firewall_rule_from_wire)
            .collect(),
    }
}

fn firewall_rule_from_wire(value: WireFwRule) -> crate::platform::firewall::config::FirewallRule {
    crate::platform::firewall::config::FirewallRule {
        table: value.table,
        chain: value.chain,
        uuid: value.uuid,
        enabled: value.enabled,
        position: value.position,
        description: value.description,
        parameters: value.parameters,
        expressions: value
            .expressions
            .into_iter()
            .map(firewall_expression_from_wire)
            .collect(),
        target: value.target,
        target_parameters: value.target_parameters,
    }
}

fn firewall_expression_from_wire(
    value: WireFwExpression,
) -> crate::platform::firewall::config::FirewallExpression {
    crate::platform::firewall::config::FirewallExpression {
        statement: value.statement.map(firewall_statement_from_wire),
    }
}

fn firewall_statement_from_wire(
    value: WireFwStatement,
) -> crate::platform::firewall::config::FirewallStatement {
    crate::platform::firewall::config::FirewallStatement {
        op: value.op,
        name: value.name,
        values: value
            .values
            .into_iter()
            .map(firewall_statement_value_from_wire)
            .collect(),
    }
}

fn firewall_statement_value_from_wire(
    value: WireFwStatementValue,
) -> crate::platform::firewall::config::FirewallStatementValue {
    crate::platform::firewall::config::FirewallStatementValue {
        key: value.key,
        value: value.value,
    }
}

use super::session::ReconnectState;

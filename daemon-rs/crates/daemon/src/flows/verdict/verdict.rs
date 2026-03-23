use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::Semaphore;

use crate::{
    bus::Bus,
    models::effective_tunables::NfqueueOverloadPolicy,
    models::{connection_state::ConnectionAttempt, verdict_rpc::VerdictReply},
    platform::ffi::nfqueue::NfqueueRuntimeState,
    platform::adapters::proto_mapper::ProtoMapperAdapter,
    platform::ports::connection_event_exporter_port::ConnectionEventExporterPort,
    services::{
        client::{
            Client, UiSessionService, enqueue_alert, warning_connection_alert,
            warning_process_alert,
        },
        config::ConfigService,
        connection::ConnectionService,
        rule::RuleService,
        stats::StatsService,
    },
};
use std::sync::Arc;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct VerdictFlow {
    bus: Bus,
    config: ConfigService,
    ui_session: UiSessionService,
    rules: RuleService,
    connections: ConnectionService,
    stats: StatsService,
    ui_ask_guard: Arc<Semaphore>,
    /// Optional per-connection event exporter (Loki, remote syslog, JSON sink, etc.)
    event_exporter: Option<Arc<dyn ConnectionEventExporterPort>>,
}

impl VerdictFlow {
    fn emit_connection_event(&self, conn: pb::Connection, rule: Option<pb::Rule>) {
        if let Some(ref exporter) = self.event_exporter {
            let config = self.config.get_snapshot();
            exporter.refresh_loggers(&config.loggers);
            exporter.on_connection_event(&conn, rule.as_ref());
        }
        self.stats.on_event(conn, rule);
    }

    fn is_self_connection(attempt: &ConnectionAttempt) -> bool {
        attempt.pid == std::process::id()
    }

    fn should_apply_unknown_default(attempt: &ConnectionAttempt, intercept_unknown: bool) -> bool {
        attempt.pid == 0 && !intercept_unknown
    }

    fn strict_miss_accounting_enabled(&self) -> bool {
        matches!(
            NfqueueRuntimeState::overload_policy(),
            NfqueueOverloadPolicy::DropFast
        )
    }

    async fn account_miss_and_apply_default(&self, request_id: u64) {
        if self.strict_miss_accounting_enabled() {
            // Strict accounting mode: miss and final verdict are counted separately.
            self.stats.on_rule_miss();
            self.apply_default_action(request_id, true).await;
        } else {
            // Go parity mode: misses are pessimistically counted as dropped.
            self.stats.on_missed_default_action();
            self.apply_default_action(request_id, false).await;
        }
    }

    fn enqueue_connection_warning_alert(&self, conn: pb::Connection) {
        enqueue_alert(&self.bus.alert_tx, warning_connection_alert(conn));
    }

    fn enqueue_process_warning_alert(&self, proc_info: &crate::models::process_state::ProcessInfo) {
        enqueue_alert(
            &self.bus.alert_tx,
            warning_process_alert(ProtoMapperAdapter::to_proto_process(proc_info)),
        );
    }

    async fn apply_default_action_on_ui_miss(
        &self,
        request_id: u64,
        proc_info: &crate::models::process_state::ProcessInfo,
        conn: pb::Connection,
    ) {
        self.emit_connection_event(conn.clone(), None);
        self.enqueue_connection_warning_alert(conn);
        self.enqueue_process_warning_alert(proc_info);
        self.account_miss_and_apply_default(request_id).await;
    }

    pub fn new(
        bus: Bus,
        config: ConfigService,
        ui_session: UiSessionService,
        rules: RuleService,
        connections: ConnectionService,
        stats: StatsService,
    ) -> Self {
        Self {
            bus,
            config,
            ui_session,
            rules,
            connections,
            stats,
            ui_ask_guard: Arc::new(Semaphore::new(1)),
            event_exporter: None,
        }
    }

    /// Attach an optional per-connection event exporter (Loki, remote syslog, JSON, etc.).
    ///
    /// The exporter is called once per resolved verdict, receiving the full
    /// connection proto and the matched rule (if any).  Exactly mirrors the
    /// Go `LoggerManager.Log(con.Serialize(), action, rname)` call in
    /// `statistics.OnConnectionEvent()`.
    ///
    /// See `platform::ports::connection_event_exporter_port::ConnectionEventExporterPort`.
    #[allow(dead_code)]
    pub fn with_event_exporter(mut self, exporter: Arc<dyn ConnectionEventExporterPort>) -> Self {
        self.event_exporter = Some(exporter);
        self
    }

    fn try_send_verdict(
        &self,
        request_id: u64,
        allow: bool,
        reject: bool,
        count_stats: bool,
        source: &'static str,
        rule_name: Option<String>,
    ) -> Option<VerdictReply> {
        let verdict = VerdictReply {
            request_id,
            allow,
            reject,
            count_stats,
            source,
            rule_name,
        };

        match self.bus.verdict_tx.try_send(verdict) {
            Ok(()) => None,
            Err(tokio::sync::mpsc::error::TrySendError::Full(next)) => Some(next),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => None,
        }
    }

    pub(crate) async fn send_verdict_when_full(&self, verdict: VerdictReply) {
        let _ = self.bus.verdict_tx.send(verdict).await;
    }

    pub(crate) fn fast_allow_with_stats_try_send(
        &self,
        request_id: u64,
        source: &'static str,
    ) -> Option<VerdictReply> {
        self.stats.on_fast_allow();
        self.allow_try_send(request_id, source, true, None)
    }

    pub(crate) fn allow_try_send(
        &self,
        request_id: u64,
        source: &'static str,
        count_stats: bool,
        rule_name: Option<String>,
    ) -> Option<VerdictReply> {
        self.try_send_verdict(request_id, true, false, count_stats, source, rule_name)
    }

    pub(crate) fn fast_deny_with_stats_try_send(
        &self,
        request_id: u64,
        reject: bool,
        source: &'static str,
        rule_name: Option<String>,
    ) -> Option<VerdictReply> {
        self.stats.on_fast_deny();
        self.deny_try_send(request_id, reject, source, true, rule_name)
    }

    pub(crate) fn deny_try_send(
        &self,
        request_id: u64,
        reject: bool,
        source: &'static str,
        count_stats: bool,
        rule_name: Option<String>,
    ) -> Option<VerdictReply> {
        self.try_send_verdict(request_id, false, reject, count_stats, source, rule_name)
    }

    pub async fn handle_connect_attempt(&self, attempt: ConnectionAttempt) {
        let request_id = attempt.request_id;
        if let Err(err) = self.process_connect_attempt(attempt).await {
            warn!(request_id, err = %err, "verdict flow failed; applying default action");
            self.account_miss_and_apply_default(request_id).await;
        }
    }

    async fn apply_default_action(&self, request_id: u64, count_stats: bool) {
        let config_snapshot = self.config.get_snapshot();
        let disconnected_default_action = config_snapshot.default_action;
        let disconnected_default_duration = config_snapshot.default_duration;
        let (action, duration) = self
            .ui_session
            .effective_defaults(disconnected_default_action, disconnected_default_duration);
        debug!(
            request_id,
            ?action,
            ?duration,
            "applying default fallback policy"
        );
        if action.allows() {
            if count_stats {
                if let Some(verdict) =
                    self.fast_allow_with_stats_try_send(request_id, "default-action")
                {
                    self.send_verdict_when_full(verdict).await;
                }
            } else {
                if let Some(verdict) =
                    self.try_send_verdict(request_id, true, false, false, "default-action", None)
                {
                    self.send_verdict_when_full(verdict).await;
                }
            }
        } else {
            if count_stats {
                if let Some(verdict) = self.fast_deny_with_stats_try_send(
                    request_id,
                    action.rejects(),
                    "default-action",
                    None,
                ) {
                    self.send_verdict_when_full(verdict).await;
                }
            } else {
                if let Some(verdict) = self.try_send_verdict(
                    request_id,
                    false,
                    action.rejects(),
                    false,
                    "default-action",
                    None,
                ) {
                    self.send_verdict_when_full(verdict).await;
                }
            }
        }
    }

    async fn process_connect_attempt(&self, attempt: ConnectionAttempt) -> Result<()> {
        if Self::is_self_connection(&attempt) {
            debug!(pid = attempt.pid, "accepting self-connection attempt");
            if let Some(verdict) =
                self.allow_try_send(attempt.request_id, "self-connection", false, None)
            {
                self.send_verdict_when_full(verdict).await;
            }
            return Ok(());
        }

        let ctx = self.connections.resolve(attempt).await;
        let attempt = ctx.attempt;
        let proc_info = ctx.process;
        let dst_host = ctx.dst_host;
        self.stats
            .on_connection_metadata(&proc_info.path, dst_host.as_deref());
        let mut pb_conn: Option<pb::Connection> = None;

        if let Some((allow, rule_name)) = self.rules.match_attempt_with_rule_name_sync(
            &attempt,
            &proc_info,
            dst_host.as_deref(),
        )? {
            if !allow.nolog {
                self.stats.on_rule_hit();
                let conn = pb_conn.take().unwrap_or_else(|| {
                    ProtoMapperAdapter::to_proto_connection(
                        &attempt,
                        &proc_info,
                        dst_host.as_deref(),
                    )
                });
                let summary_rule = allow.to_summary_rule();
                self.emit_connection_event(conn, Some(summary_rule));
            }
            if allow.allow {
                let verdict = if allow.nolog {
                    self.allow_try_send(attempt.request_id, "runtime-rule", false, Some(rule_name))
                } else {
                    self.allow_try_send(attempt.request_id, "runtime-rule", true, Some(rule_name))
                };
                if let Some(verdict) = verdict {
                    self.send_verdict_when_full(verdict).await;
                }
            } else {
                let verdict = if allow.nolog {
                    self.deny_try_send(
                        attempt.request_id,
                        allow.reject,
                        "runtime-rule",
                        false,
                        Some(rule_name),
                    )
                } else {
                    self.fast_deny_with_stats_try_send(
                        attempt.request_id,
                        allow.reject,
                        "runtime-rule",
                        Some(rule_name),
                    )
                };
                if let Some(verdict) = verdict {
                    self.send_verdict_when_full(verdict).await;
                }
            }
            return Ok(());
        }

        let config_snapshot = self.config.get_snapshot();

        if Self::should_apply_unknown_default(&attempt, config_snapshot.intercept_unknown) {
            let conn = pb_conn.take().unwrap_or_else(|| {
                ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
            });
            self.emit_connection_event(conn, None);
            self.account_miss_and_apply_default(attempt.request_id).await;
            return Ok(());
        }

        let Ok(_ask_guard) = self.ui_ask_guard.clone().try_acquire_owned() else {
            debug!(
                request_id = attempt.request_id,
                "ui ask already in progress; applying default action"
            );
            let conn = pb_conn.take().unwrap_or_else(|| {
                ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
            });
            self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                .await;
            return Ok(());
        };

        let client_addr = config_snapshot.client_addr.as_str();
        let mut client = match Client::connect_with_config(&config_snapshot).await {
            Ok(client) => client,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "ui connect failed while handling miss; applying default action: {err}");
                let conn = pb_conn.take().unwrap_or_else(|| {
                    ProtoMapperAdapter::to_proto_connection(
                        &attempt,
                        &proc_info,
                        dst_host.as_deref(),
                    )
                });
                self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                    .await;
                return Ok(());
            }
        };
        let conn_for_ui = pb_conn
            .get_or_insert_with(|| {
                ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
            })
            .clone();
        let rule = match client.ask_rule(conn_for_ui).await {
            Ok(rule) => rule,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "ui ask_rule failed while handling miss; applying default action: {err}");
                let conn = pb_conn.take().unwrap_or_else(|| {
                    ProtoMapperAdapter::to_proto_connection(
                        &attempt,
                        &proc_info,
                        dst_host.as_deref(),
                    )
                });
                self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                    .await;
                return Ok(());
            }
        };
        let decision = self.rules.upsert_from_proto(&rule).await?;
        let ui_rule_name = rule.name;

        if !decision.nolog {
            self.stats.on_rule_hit();
            let conn = pb_conn.take().unwrap_or_else(|| {
                ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
            });
            let summary_rule = decision.to_summary_rule();
            self.emit_connection_event(conn, Some(summary_rule));
        }

        if decision.allow {
            let verdict = if decision.nolog {
                self.allow_try_send(attempt.request_id, "ui-rule", false, Some(ui_rule_name))
            } else {
                self.allow_try_send(attempt.request_id, "ui-rule", true, Some(ui_rule_name))
            };
            if let Some(verdict) = verdict {
                self.send_verdict_when_full(verdict).await;
            }
        } else {
            let verdict = if decision.nolog {
                self.deny_try_send(
                    attempt.request_id,
                    decision.reject,
                    "ui-rule",
                    false,
                    Some(ui_rule_name),
                )
            } else {
                self.fast_deny_with_stats_try_send(
                    attempt.request_id,
                    decision.reject,
                    "ui-rule",
                    Some(ui_rule_name),
                )
            };
            if let Some(verdict) = verdict {
                self.send_verdict_when_full(verdict).await;
            }
        }

        Ok(())
    }
}

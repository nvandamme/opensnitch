use anyhow::Result;
use opensnitch_proto::pb;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::{
    bus::Bus,
    models::{connection_state::ConnectionAttempt, verdict_rpc::VerdictReply},
    platform::adapters::proto_mapper::ProtoMapperAdapter,
    platform::ports::connection_event_exporter_port::ConnectionEventExporterPort,
    services::{
        client::{AlertBuffer, ClientService, GrpcChannelCache},
        config::ConfigService,
        connection::ConnectionService,
        policy_tx::{PolicyOwner, PolicyTxRequest, global_policy_tx},
        rule::RuleService,
        stats::StatsService,
    },
};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::models::{
    rule_match_decision::RuleMatchDecision,
    rule_record::RuleAction,
};

#[derive(Debug)]
pub(super) struct VerdictRulePersistRequest {
    pub(super) rule: pb::Rule,
    pub(super) owner: PolicyOwner,
    pub(super) idempotency_key: String,
}

#[derive(Clone)]
pub struct VerdictFlow {
    pub(super) bus: Bus,
    pub(super) alert_buffer: AlertBuffer,
    pub(super) config: ConfigService,
    pub(super) client_service: ClientService,
    pub(super) rules: RuleService,
    pub(super) connections: ConnectionService,
    pub(super) stats: StatsService,
    pub(super) pending_decisions: Arc<DashMap<u64, u64>>,
    pub(super) rule_persist_tx: mpsc::Sender<VerdictRulePersistRequest>,
    /// Cached gRPC channel for UI miss/ask_rule calls.
    pub(super) grpc_cache: GrpcChannelCache,
    /// Optional per-connection event exporter (Loki, remote syslog, JSON sink, etc.)
    pub(super) event_exporter: Option<Arc<dyn ConnectionEventExporterPort>>,
}

impl VerdictFlow {
    pub fn new(
        bus: Bus,
        alert_buffer: AlertBuffer,
        config: ConfigService,
        client_service: ClientService,
        rules: RuleService,
        connections: ConnectionService,
        stats: StatsService,
    ) -> Self {
        let (rule_persist_tx, mut rule_persist_rx) = mpsc::channel::<VerdictRulePersistRequest>(256);
        let rules_for_worker = rules.clone();
        tokio::spawn(async move {
            while let Some(request) = rule_persist_rx.recv().await {
                let previous_rules = rules_for_worker.get_proto_snapshot();
                let rule_for_apply = request.rule.clone();
                let rule_name = request.rule.name.clone();

                let tx_result = global_policy_tx()
                    .execute(
                        PolicyTxRequest {
                            idempotency_key: request.idempotency_key,
                            owner: request.owner,
                            expected_revision: None,
                            operations: vec![format!("upsert:{rule_name}")],
                        },
                        || {
                            let rules = rules_for_worker.clone();
                            async move {
                                rules
                                    .upsert_from_proto(&rule_for_apply)
                                    .await
                                    .map(|_| ())
                                    .map_err(|err| err.to_string())
                            }
                        },
                        || {
                            let rules = rules_for_worker.clone();
                            let snapshot = previous_rules.clone();
                            async move { Self::restore_rules_snapshot(&rules, &snapshot).await }
                        },
                    )
                    .await;

                if let Err(err) = tx_result {
                    warn!(rule = %rule_name, "async verdict rule persist failed: {:?}", err);
                }
            }
        });

        Self {
            bus,
            alert_buffer,
            config,
            client_service,
            rules,
            connections,
            stats,
            pending_decisions: Arc::new(DashMap::new()),
            rule_persist_tx,
            grpc_cache: GrpcChannelCache::default(),
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

    pub(super) fn try_send_verdict(
        &self,
        request_id: u64,
        allow: bool,
        reject: bool,
        count_stats: bool,
        source: &'static str,
        rule_name: Option<Arc<str>>,
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
        rule_name: Option<Arc<str>>,
    ) -> Option<VerdictReply> {
        self.try_send_verdict(request_id, true, false, count_stats, source, rule_name)
    }

    pub(crate) fn fast_deny_with_stats_try_send(
        &self,
        request_id: u64,
        reject: bool,
        source: &'static str,
        rule_name: Option<Arc<str>>,
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
        rule_name: Option<Arc<str>>,
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

    pub(super) async fn apply_default_action(&self, request_id: u64, count_stats: bool) {
        let config_snapshot = self.config.get_snapshot();
        let disconnected_default_action = config_snapshot.default_action;
        let disconnected_default_duration = config_snapshot.default_duration;
        let (action, duration) = self
            .client_service
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

        let decision_key = Self::decision_key_hash(&attempt, &proc_info, dst_host.as_deref());
        let Some(decision_epoch) = self.begin_decision_epoch(decision_key) else {
            debug!(
                request_id = attempt.request_id,
                "ui ask for connection already in progress; applying default action"
            );
            let conn = pb_conn.take().unwrap_or_else(|| {
                ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
            });
            self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                .await;
            return Ok(());
        };

        let client_addr = config_snapshot.client_addr.as_str();
        let mut client = match ClientService::connect_or_reuse(&config_snapshot, &self.grpc_cache).await {
            Ok(client) => client,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "ui connect failed while handling miss; applying default action: {err}");
                self.grpc_cache.invalidate();
                let conn = pb_conn.take().unwrap_or_else(|| {
                    ProtoMapperAdapter::to_proto_connection(
                        &attempt,
                        &proc_info,
                        dst_host.as_deref(),
                    )
                });
                self.end_decision_epoch(decision_key, decision_epoch);
                self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                    .await;
                return Ok(());
            }
        };
        let conn_for_ui = pb_conn.take().unwrap_or_else(|| {
            ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
        });
        let rule = match client.ask_rule(conn_for_ui).await {
            Ok(rule) => rule,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "ui ask_rule failed while handling miss; applying default action: {err}");
                self.grpc_cache.invalidate();
                let conn = pb_conn.take().unwrap_or_else(|| {
                    ProtoMapperAdapter::to_proto_connection(
                        &attempt,
                        &proc_info,
                        dst_host.as_deref(),
                    )
                });
                self.end_decision_epoch(decision_key, decision_epoch);
                self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                    .await;
                return Ok(());
            }
        };

        if !self
            .is_decision_epoch_current(decision_key, decision_epoch)
        {
            debug!(request_id = attempt.request_id, "stale ui decision ignored");
            let conn = pb_conn.take().unwrap_or_else(|| {
                ProtoMapperAdapter::to_proto_connection(&attempt, &proc_info, dst_host.as_deref())
            });
            self.apply_default_action_on_ui_miss(attempt.request_id, &proc_info, conn)
                .await;
            return Ok(());
        }

        let decision = RuleMatchDecision::from_rule(RuleAction::from_name(&rule.action), rule.nolog);
        self.end_decision_epoch(decision_key, decision_epoch);
        let ui_rule_name: Arc<str> = Arc::from(rule.name.as_str());
        self.enqueue_rule_persist(
            attempt.request_id,
            rule,
            format!("verdict-ui-rule:{}:{}", decision_key, decision_epoch),
        );

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

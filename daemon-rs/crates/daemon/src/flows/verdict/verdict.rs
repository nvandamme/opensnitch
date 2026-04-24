use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::mpsc;
use transport_wire_core::{ClientTransportConnectorPort, ClientTransportPort, WireRule};

use crate::{
    bus::Bus,
    models::{
        audit::{AuditEvent, AuditEventKind, VerdictAction, VerdictSource},
        connection_state::ConnectionAttempt,
        verdict_rpc::VerdictReply,
    },
    platform::ports::connection_event_exporter_port::ConnectionEventExporterPort,
    platform::ports::proto_mapper_port::ProtoMapperPort,
    services::rule::rule_record_from_wire,
    services::{
        audit::AuditService,
        client::{AlertBuffer, ClientService, ClientTransportConnector, WireSessionCache},
        config::ConfigService,
        connection::ConnectionService,
        policy_tx::{PolicyOwner, PolicyTxRequest, global_policy_tx},
        rule::RuleService,
        stats::StatsService,
    },
};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::models::{rule_match_decision::RuleMatchDecision, rule_record::RuleRecord};

#[derive(Debug)]
pub(super) struct VerdictRulePersistRequest {
    pub(super) rule: RuleRecord,
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
    /// Cached transport connector for client miss/ask_rule calls.
    pub(super) transport_connector: ClientTransportConnector,
    /// Optional per-connection event exporter (Loki, remote syslog, JSON sink, etc.)
    pub(super) event_exporter: Option<Arc<dyn ConnectionEventExporterPort>>,
    pub(super) audit: AuditService,
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
        audit: AuditService,
    ) -> Self {
        let (rule_persist_tx, mut rule_persist_rx) =
            mpsc::channel::<VerdictRulePersistRequest>(256);
        let rules_for_worker = rules.clone();
        tokio::spawn(async move {
            while let Some(request) = rule_persist_rx.recv().await {
                let previous_rules = rules_for_worker.get_rule_record_snapshot();
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
                                    .upsert_rule_record(rule_for_apply)
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
                    warn!(rule = %rule_name, "async verdict rule persist failed: {}", err);
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
            transport_connector: ClientTransportConnector::new(WireSessionCache::default()),
            event_exporter: None,
            audit,
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
    pub fn with_event_exporter(mut self, exporter: Arc<dyn ConnectionEventExporterPort>) -> Self {
        self.event_exporter = Some(exporter);
        self
    }

    /// Inline this hot-path helper so the compiler can eliminate the try_send
    /// boilerplate and fold the branch into the caller.
    #[inline]
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
        self.audit
            .emit(AuditEvent::hot(AuditEventKind::VerdictAction(
                VerdictAction::VerdictQueueBackpressure {
                    request_id: verdict.request_id,
                    source: VerdictSource::from_verdict_source(verdict.source),
                },
            )));
        let _ = self.bus.verdict_tx.send(verdict).await;
    }

    /// Unified verdict emission: try_send first, then fall back to async send
    /// when the channel is full. Reduces code duplication across all verdict
    /// call sites (runtime-rule, client-rule, default-action).
    pub(crate) async fn emit_verdict(
        &self,
        request_id: u64,
        allow: bool,
        reject: bool,
        count_stats: bool,
        source: &'static str,
        rule_name: Option<Arc<str>>,
    ) {
        // Fast path: no stats, no rule name — single try_send call.
        if !count_stats && rule_name.is_none() {
            if let Some(verdict) =
                self.try_send_verdict(request_id, allow, reject, false, source, None)
            {
                self.send_verdict_when_full(verdict).await;
            }
            return;
        }

        // Stats path: count before sending.
        if count_stats {
            if allow {
                self.stats.on_fast_allow();
            } else {
                self.stats.on_fast_deny();
            }
        }

        if let Some(verdict) =
            self.try_send_verdict(request_id, allow, reject, count_stats, source, rule_name)
        {
            self.send_verdict_when_full(verdict).await;
        }
    }

    #[inline]
    pub(crate) fn allow_try_send(
        &self,
        request_id: u64,
        source: &'static str,
        count_stats: bool,
        rule_name: Option<Arc<str>>,
    ) -> Option<VerdictReply> {
        self.try_send_verdict(request_id, true, false, count_stats, source, rule_name)
    }

    #[inline]
    pub async fn handle_connect_attempt(&self, attempt: ConnectionAttempt) {
        let request_id = attempt.request_id;
        if let Err(err) = self.process_connect_attempt(attempt).await {
            warn!(request_id, err = %err, "verdict flow failed; applying default action");
            self.account_miss_and_apply_default(request_id).await;
        }
    }

    /// Inline the default-action path so the compiler can eliminate dead
    /// branches (e.g., count_stats=false paths) at inlining time.
    #[inline]
    pub(super) async fn apply_default_action(&self, request_id: u64, count_stats: bool) {
        let config_snapshot = self.config.get_snapshot();
        let disconnected_default_action = config_snapshot.default_action;
        let disconnected_default_duration = config_snapshot.default_duration;
        let (action, _duration) = self
            .client_service
            .effective_defaults(disconnected_default_action, disconnected_default_duration);
        debug!(request_id, ?action, "applying default fallback policy");
        // Use emit_verdict for all paths — eliminates the count_stats branching
        // by delegating stats counting into the unified helper.
        let allow = action.allows();
        self.emit_verdict(
            request_id,
            allow,
            action.rejects(),
            count_stats,
            "default-action",
            None,
        )
        .await;
    }

    /// Build a WireRule summary for runtime-matched rules.
    #[inline]
    fn summary_rule_to_wire(
        summary: crate::models::rule_match_decision::RuleMatchSummary,
    ) -> WireRule {
        WireRule {
            created: 0,
            name: "runtime-match".to_string(),
            description: "matched existing runtime rule".to_string(),
            enabled: true,
            precedence: false,
            nolog: summary.nolog,
            action: summary.action.to_owned(),
            duration: "always".to_owned(),
            operator: None,
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
        let wire_conn = Arc::new(ProtoMapperPort::to_wire_connection(
            &attempt,
            &proc_info,
            dst_host.as_deref(),
        ));
        self.stats
            .on_connection_metadata(&proc_info.path, dst_host.as_deref());

        if let Some((quick_decision, rule_name)) = self.rules.match_attempt_with_rule_name_sync(
            &attempt,
            &proc_info,
            dst_host.as_deref(),
        )? {
            if !quick_decision.nolog {
                self.stats.on_rule_hit(&rule_name);
                let summary_rule =
                    Arc::new(Self::summary_rule_to_wire(quick_decision.to_summary()));
                self.emit_connection_event(Arc::clone(&wire_conn), Some(summary_rule));
            }
            // Unified verdict emission for matched rules — eliminates 6 nearly-identical
            // allow/deny blocks into a single call site with the same semantics.
            self.emit_verdict(
                attempt.request_id,
                quick_decision.allow,
                quick_decision.reject,
                !quick_decision.nolog,
                "runtime-rule",
                Some(rule_name),
            )
            .await;
            return Ok(());
        }

        let config_snapshot = self.config.get_snapshot();

        if Self::should_apply_unknown_default(&attempt, config_snapshot.intercept_unknown) {
            self.emit_connection_event(Arc::clone(&wire_conn), None);
            self.account_miss_and_apply_default(attempt.request_id)
                .await;
            return Ok(());
        }

        let decision_key = Self::decision_key_hash(&attempt, &proc_info, dst_host.as_deref());
        let Some(decision_epoch) = self.begin_decision_epoch(decision_key) else {
            debug!(
                request_id = attempt.request_id,
                "client ask for connection already in progress; applying default action"
            );
            self.apply_default_action_on_client_miss(
                attempt.request_id,
                &proc_info,
                Arc::clone(&wire_conn),
            )
            .await;
            return Ok(());
        };

        let client_addr = config_snapshot.client_addr.as_str();
        let mut client = match ClientTransportConnectorPort::connect_or_reuse(
            &self.transport_connector,
            &config_snapshot,
        )
        .await
        {
            Ok(client) => client,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "client connect failed while handling miss; applying default action: {err}");
                ClientTransportConnectorPort::invalidate(&self.transport_connector);
                self.end_decision_epoch(decision_key, decision_epoch);
                self.apply_default_action_on_client_miss(
                    attempt.request_id,
                    &proc_info,
                    Arc::clone(&wire_conn),
                )
                .await;
                return Ok(());
            }
        };
        // ask_rule is the final transport call and currently requires an owned
        // payload. Keep the daemon event/alert paths on the shared immutable
        // snapshot and materialize ownership only at this wire boundary.
        let wire_conn_for_ask = wire_conn.as_ref().clone();
        let rule = match ClientTransportPort::ask_rule(&mut client, wire_conn_for_ask).await {
            Ok(rule) => rule,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "client ask_rule failed while handling miss; applying default action: {err}");
                ClientTransportConnectorPort::invalidate(&self.transport_connector);
                self.end_decision_epoch(decision_key, decision_epoch);
                self.apply_default_action_on_client_miss(
                    attempt.request_id,
                    &proc_info,
                    Arc::clone(&wire_conn),
                )
                .await;
                return Ok(());
            }
        };

        if !self.is_decision_epoch_current(decision_key, decision_epoch) {
            debug!(
                request_id = attempt.request_id,
                "stale client decision ignored"
            );
            self.apply_default_action_on_client_miss(
                attempt.request_id,
                &proc_info,
                Arc::clone(&wire_conn),
            )
            .await;
            return Ok(());
        }

        let rule_record = rule_record_from_wire(&rule);
        let decision = RuleMatchDecision::from_rule(rule_record.action, rule_record.nolog);
        self.end_decision_epoch(decision_key, decision_epoch);
        self.audit
            .emit(AuditEvent::hot(AuditEventKind::VerdictAction(
                VerdictAction::AskRuleRulePersisted {
                    request_id: attempt.request_id,
                    rule_name: rule_record.name.clone(),
                    action: rule_record.action,
                },
            )));
        let client_rule_name: Arc<str> = Arc::from(rule_record.name.as_str());
        use std::fmt::Write as _;
        let mut idem_buf = String::with_capacity(64);
        let _ = write!(
            &mut idem_buf,
            "verdict-client-rule:{decision_key}:{decision_epoch}"
        );
        self.enqueue_rule_persist(attempt.request_id, rule_record, idem_buf);

        if !decision.nolog {
            self.stats.on_rule_hit(&client_rule_name);
            let summary_rule = Arc::new(Self::summary_rule_to_wire(decision.to_summary()));
            self.emit_connection_event(wire_conn, Some(summary_rule));
        }

        // Unified verdict emission for client-rule — same pattern as runtime-rule above.
        self.emit_verdict(
            attempt.request_id,
            decision.allow,
            decision.reject,
            !decision.nolog,
            "client-rule",
            Some(client_rule_name),
        )
        .await;

        Ok(())
    }
}

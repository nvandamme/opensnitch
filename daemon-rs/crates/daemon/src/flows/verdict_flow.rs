use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::Mutex;

use crate::{
    bus::Bus,
    client::client::Client,
    models::{
        connection_state::ConnectionAttempt,
        process_state::ProcessInfo,
        ui_alert::{UiAlert, enqueue_alert},
        verdict_rpc::VerdictReply,
    },
    services::{
        config_service::ConfigService, connection_service::ConnectionService,
        rule_service::RuleService, stats_service::StatsService,
        ui_session_service::UiSessionService,
    },
};
use std::sync::Arc;
use tracing::{debug, warn};

const VERDICT_TRY_SEND_SPINS: usize = 4;
const VERDICT_TRY_SEND_YIELD_AFTER: usize = 2;

#[derive(Clone)]
pub struct VerdictFlow {
    bus: Bus,
    config: ConfigService,
    ui_session: UiSessionService,
    rules: RuleService,
    connections: ConnectionService,
    stats: StatsService,
    ui_ask_guard: Arc<Mutex<()>>,
}

impl VerdictFlow {
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
            ui_ask_guard: Arc::new(Mutex::new(())),
        }
    }

    #[cfg(test)]
    pub async fn handle_event(
        &self,
        _event: crate::models::kernel_event::KernelEvent,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn send_verdict(
        &self,
        request_id: u64,
        allow: bool,
        reject: bool,
        count_stats: bool,
        source: &'static str,
        rule_name: Option<String>,
    ) {
        let mut verdict = VerdictReply {
            request_id,
            allow,
            reject,
            count_stats,
            source,
            rule_name,
        };

        for attempt in 0..VERDICT_TRY_SEND_SPINS {
            match self.bus.verdict_tx.try_send(verdict) {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Full(next)) => {
                    verdict = next;
                    if attempt + 1 >= VERDICT_TRY_SEND_YIELD_AFTER {
                        tokio::task::yield_now().await;
                    } else {
                        std::hint::spin_loop();
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
            }
        }

        let _ = self.bus.verdict_tx.send(verdict).await;
    }

    pub async fn fast_allow(&self, request_id: u64, source: &'static str) {
        self.send_verdict(request_id, true, false, true, source, None)
            .await;
    }

    pub async fn fast_allow_without_stats(&self, request_id: u64, source: &'static str) {
        self.send_verdict(request_id, true, false, false, source, None)
            .await;
    }

    pub async fn fast_allow_with_stats(&self, request_id: u64, source: &'static str) {
        self.stats.on_fast_allow();
        self.fast_allow(request_id, source).await;
    }

    pub async fn fast_deny(&self, request_id: u64, reject: bool, source: &'static str) {
        self.send_verdict(request_id, false, reject, true, source, None)
            .await;
    }

    pub async fn fast_deny_without_stats(
        &self,
        request_id: u64,
        reject: bool,
        source: &'static str,
    ) {
        self.send_verdict(request_id, false, reject, false, source, None)
            .await;
    }

    pub async fn fast_deny_with_stats(&self, request_id: u64, reject: bool, source: &'static str) {
        self.stats.on_fast_deny();
        self.fast_deny(request_id, reject, source).await;
    }

    pub async fn handle_connect_attempt(&self, attempt: ConnectionAttempt) {
        let request_id = attempt.request_id;
        if let Err(err) = self.process_connect_attempt(attempt).await {
            warn!(request_id, err = %err, "verdict flow failed; applying default action");
            self.stats.on_missed_default_action();
            self.apply_default_action(request_id, false).await;
        }
    }

    async fn apply_default_action(&self, request_id: u64, count_stats: bool) {
        let disconnected_default_action = self.config.default_action().await;
        let disconnected_default_duration = self.config.default_duration().await;
        let action = self
            .ui_session
            .effective_default_action(disconnected_default_action)
            .await;
        let duration = self
            .ui_session
            .effective_default_duration(disconnected_default_duration)
            .await;
        debug!(
            request_id,
            ?action,
            ?duration,
            "applying default fallback policy"
        );
        if action.allows() {
            if count_stats {
                self.fast_allow(request_id, "default-action").await;
            } else {
                self.fast_allow_without_stats(request_id, "default-action")
                    .await;
            }
        } else {
            if count_stats {
                self.fast_deny_with_stats(request_id, action.rejects(), "default-action")
                    .await;
            } else {
                self.fast_deny_without_stats(request_id, action.rejects(), "default-action")
                    .await;
            }
        }
    }

    async fn process_connect_attempt(&self, attempt: ConnectionAttempt) -> Result<()> {
        if attempt.pid == std::process::id() {
            debug!(pid = attempt.pid, "accepting self-connection attempt");
            self.fast_allow_with_stats(attempt.request_id, "self-connection")
                .await;
            return Ok(());
        }

        let ctx = self.connections.resolve(attempt).await;
        let attempt = ctx.attempt;
        let proc_info = ctx.process;
        let dst_host = ctx.dst_host;
        self.stats
            .on_connection_metadata(&proc_info.path, dst_host.as_deref());
        let pb_conn = ctx.pb_conn;

        if let Some((allow, rule_name)) = self
            .rules
            .match_attempt_with_rule_name(&attempt, &proc_info, dst_host.as_deref())
            .await?
        {
            if !allow.nolog {
                self.stats.on_rule_hit();
                self.stats
                    .on_event(pb_conn.clone(), Some(decision_rule_summary(allow)));
            }
            if allow.allow {
                self.send_verdict(
                    attempt.request_id,
                    true,
                    false,
                    true,
                    "runtime-rule",
                    Some(rule_name),
                )
                .await;
            } else {
                self.stats.on_fast_deny();
                self.send_verdict(
                    attempt.request_id,
                    false,
                    allow.reject,
                    true,
                    "runtime-rule",
                    Some(rule_name),
                )
                .await;
            }
            return Ok(());
        }

        if attempt.pid == 0 && !self.config.intercept_unknown().await {
            self.stats.on_missed_default_action();
            self.apply_default_action(attempt.request_id, false).await;
            return Ok(());
        }

        let Ok(_ask_guard) = self.ui_ask_guard.try_lock() else {
            debug!(
                request_id = attempt.request_id,
                "ui ask already in progress; applying default action"
            );
            enqueue_alert(
                &self.bus.alert_tx,
                UiAlert::warning_connection(pb_conn.clone()),
            );
            enqueue_alert(
                &self.bus.alert_tx,
                UiAlert::warning_process(to_proto_process(&proc_info)),
            );
            self.stats.on_missed_default_action();
            self.apply_default_action(attempt.request_id, false).await;
            return Ok(());
        };

        let config_snapshot = self.config.snapshot().await;
        let client_addr = config_snapshot.client_addr.clone();
        let mut client = match Client::connect_with_config(&config_snapshot).await {
            Ok(client) => client,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "ui connect failed while handling miss; applying default action: {err}");
                enqueue_alert(
                    &self.bus.alert_tx,
                    UiAlert::warning_connection(pb_conn.clone()),
                );
                self.stats.on_missed_default_action();
                self.apply_default_action(attempt.request_id, false).await;
                return Ok(());
            }
        };
        let rule = match client.ask_rule(pb_conn.clone()).await {
            Ok(rule) => rule,
            Err(err) => {
                debug!(request_id = attempt.request_id, addr = %client_addr, "ui ask_rule failed while handling miss; applying default action: {err}");
                enqueue_alert(
                    &self.bus.alert_tx,
                    UiAlert::warning_connection(pb_conn.clone()),
                );
                self.stats.on_missed_default_action();
                self.apply_default_action(attempt.request_id, false).await;
                return Ok(());
            }
        };
        let decision = self.rules.upsert_from_proto(&rule).await?;

        if !decision.nolog {
            self.stats.on_rule_hit();
            self.stats
                .on_event(pb_conn, Some(decision_rule_summary(decision)));
        }

        if decision.allow {
            self.send_verdict(
                attempt.request_id,
                true,
                false,
                true,
                "ui-rule",
                Some(rule.name.clone()),
            )
            .await;
        } else {
            self.stats.on_fast_deny();
            self.send_verdict(
                attempt.request_id,
                false,
                decision.reject,
                true,
                "ui-rule",
                Some(rule.name.clone()),
            )
            .await;
        }

        Ok(())
    }
}

fn to_proto_process(info: &ProcessInfo) -> pb::Process {
    pb::Process {
        pid: info.pid as u64,
        ppid: 0,
        uid: 0,
        comm: String::new(),
        path: info.path.clone(),
        args: info.args.clone(),
        env: info
            .env_preview
            .iter()
            .filter_map(|entry| {
                entry
                    .split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect(),
        cwd: info.cwd.clone().unwrap_or_default(),
        checksums: {
            let mut checksums = std::collections::HashMap::new();
            if let Some(md5) = &info.process_hash_md5 {
                checksums.insert("md5".to_string(), md5.clone());
            }
            if let Some(sha1) = &info.process_hash_sha1 {
                checksums.insert("sha1".to_string(), sha1.clone());
            }
            if let Some(sha256) = &info.process_hash {
                checksums.insert("sha256".to_string(), sha256.clone());
            }
            checksums
        },
        io_reads: 0,
        io_writes: 0,
        net_reads: 0,
        net_writes: 0,
        process_tree: info
            .parent_chain
            .iter()
            .map(|node| pb::StringInt {
                key: node.path.clone(),
                value: node.pid,
            })
            .collect(),
    }
}

pub(crate) fn decision_rule_summary(
    decision: crate::services::rule_service::RuleMatchDecision,
) -> pb::Rule {
    pb::Rule {
        created: 0,
        name: "runtime-match".to_owned(),
        description: "matched existing runtime rule".to_owned(),
        enabled: true,
        precedence: false,
        nolog: decision.nolog,
        action: if decision.allow {
            "allow".to_owned()
        } else if decision.reject {
            "reject".to_owned()
        } else {
            "deny".to_owned()
        },
        duration: "always".to_owned(),
        operator: None,
    }
}

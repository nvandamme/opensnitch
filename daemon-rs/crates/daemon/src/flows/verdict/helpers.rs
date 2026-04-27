/// Private helper methods for `VerdictFlow`.
///
/// Extracted from `verdict.rs` per DESIGN_RULES §3: internal decision-engine
/// helpers are a separate concern from the public-API entry points
/// (`handle_connect_attempt`, `process_connect_attempt`, constructor) that
/// stay in `verdict.rs`.
use std::sync::Arc;

use transport_wire_core::{WireConnection, WireProcess, WireRule, WireStringInt};

use crate::{
    config::{AskFallbackPolicy, DefaultAction},
    models::audit::{AuditEvent, AuditEventKind, VerdictAction},
    models::connection::state::ConnectionAttempt,
    models::process::state::ProcessInfo,
    models::rule::record::RuleRecord,
    platform::nfqueue::state::NfqueueRuntimeState,
    services::client::enqueue_alert,
    services::client::{warning_connection_alert, warning_process_alert},
    services::policy::PolicyOwner,
    tunables::effective::NfqueueOverloadPolicy,
};

use super::verdict::{VerdictFlow, VerdictRulePersistRequest};

impl VerdictFlow {
    pub(super) async fn restore_rules_snapshot(
        rules: &crate::services::rule::RuleService,
        snapshot: &[RuleRecord],
    ) -> Result<(), String> {
        use std::collections::BTreeSet;
        let target_names = snapshot
            .iter()
            .map(|rule| rule.name.clone())
            .collect::<BTreeSet<_>>();
        let current = rules.get_wire_snapshot();

        for rule in current.as_ref() {
            if !target_names.contains(&rule.name) {
                rules
                    .delete_by_name(&rule.name)
                    .await
                    .map_err(|err| format!("rollback delete {}: {err}", rule.name))?;
            }
        }

        for rule in snapshot {
            rules
                .upsert_rule_record(rule.clone())
                .await
                .map_err(|err| format!("rollback upsert {}: {err}", rule.name))?;
        }

        Ok(())
    }

    pub(super) fn enqueue_rule_persist(
        &self,
        request_id: u64,
        rule: RuleRecord,
        idempotency_key: String,
    ) {
        let owner = self
            .client_service
            .primary_owner()
            .map(PolicyOwner::from)
            .unwrap_or(PolicyOwner::System);
        let request = VerdictRulePersistRequest {
            rule,
            owner,
            idempotency_key,
        };
        if let Err(err) = self.rule_persist_tx.try_send(request) {
            tracing::warn!(
                request_id,
                "dropping async verdict rule persist request: {err}"
            );
        }
    }

    pub(super) fn decision_key_hash(
        attempt: &ConnectionAttempt,
        proc_info: &crate::models::process::state::ProcessInfo,
        dst_host: Option<&str>,
    ) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        proc_info.path.hash(&mut h);
        attempt.uid.hash(&mut h);
        attempt.pid.hash(&mut h);
        attempt.src_addr.hash(&mut h);
        attempt.dst_addr.hash(&mut h);
        attempt.dst_port.hash(&mut h);
        attempt.protocol.hash(&mut h);
        dst_host.unwrap_or_default().hash(&mut h);
        h.finish()
    }

    pub(super) fn begin_decision_epoch(&self, key: u64) -> Option<u64> {
        match self.pending_decisions.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(_) => None,
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(1);
                Some(1)
            }
        }
    }

    pub(super) fn is_decision_epoch_current(&self, key: u64, epoch: u64) -> bool {
        self.pending_decisions
            .get(&key)
            .is_some_and(|current| *current == epoch)
    }

    pub(super) fn end_decision_epoch(&self, key: u64, epoch: u64) {
        if let dashmap::mapref::entry::Entry::Occupied(e) = self.pending_decisions.entry(key) {
            if *e.get() == epoch {
                e.remove();
            }
        }
    }

    /// Emit a connection event to the event exporter (if configured) and stats service.
    #[inline]
    pub(super) fn emit_connection_event(
        &self,
        conn: Arc<WireConnection>,
        rule: Option<Arc<WireRule>>,
    ) {
        if let Some(ref exporter) = self.event_exporter {
            let config = self.config.get_snapshot();
            exporter.refresh_loggers(&config.loggers);
            exporter.on_connection_event(conn.as_ref(), rule.as_deref());
        }
        self.stats.on_event(conn, rule);
    }

    pub(super) fn is_self_connection(attempt: &ConnectionAttempt) -> bool {
        attempt.pid == std::process::id()
    }

    pub(super) fn should_apply_unknown_default(
        attempt: &ConnectionAttempt,
        intercept_unknown: bool,
    ) -> bool {
        attempt.pid == 0 && !intercept_unknown
    }

    pub(super) fn strict_miss_accounting_enabled(&self) -> bool {
        matches!(
            NfqueueRuntimeState::overload_policy(),
            NfqueueOverloadPolicy::DropFast
        )
    }

    pub(super) async fn account_miss_and_apply_default(&self, request_id: u64) {
        if self.strict_miss_accounting_enabled() {
            self.stats.on_rule_miss();
            self.apply_default_action(request_id, true).await;
        } else {
            self.stats.on_missed_default_action();
            self.apply_default_action(request_id, false).await;
        }
    }

    pub(super) fn enqueue_connection_warning_alert(&self, conn: &WireConnection) {
        enqueue_alert(
            &self.alert_buffer,
            &self.bus.alert_tx,
            warning_connection_alert(conn),
        );
    }

    pub(super) fn enqueue_process_warning_alert(&self, proc_info: &ProcessInfo) {
        // Pre-size checksums HashMap to capacity 3 (max possible hash entries)
        // to avoid the default 8-bucket allocation + potential reallocation.
        let mut checksums = std::collections::HashMap::with_capacity(3);
        if let Some(hash) = proc_info
            .process_hash_md5
            .as_ref()
            .filter(|v| !v.is_empty())
        {
            checksums.insert("md5".into(), hash.clone());
        }
        if let Some(hash) = proc_info
            .process_hash_sha1
            .as_ref()
            .filter(|v| !v.is_empty())
        {
            checksums.insert("sha1".into(), hash.clone());
        }
        if let Some(hash) = proc_info.process_hash.as_ref().filter(|v| !v.is_empty()) {
            checksums.insert("sha256".into(), hash.clone());
        }

        let env = if !proc_info.env_map.is_empty() {
            proc_info.env_map.clone()
        } else {
            // Pre-size to exact env_preview length to avoid reallocation.
            let mut env = std::collections::HashMap::with_capacity(proc_info.env_preview.len());
            for entry in &proc_info.env_preview {
                if let Some((key, value)) = entry.split_once('=') {
                    env.insert(key.to_string(), value.to_string());
                }
            }
            env
        };

        enqueue_alert(
            &self.alert_buffer,
            &self.bus.alert_tx,
            warning_process_alert(WireProcess {
                pid: proc_info.pid as u64,
                ppid: 0,
                uid: 0,
                comm: String::new(),
                path: proc_info.path.clone(),
                args: proc_info.args.clone(),
                env,
                cwd: proc_info.cwd.clone().unwrap_or_default(),
                checksums,
                io_reads: 0,
                io_writes: 0,
                net_reads: 0,
                net_writes: 0,
                process_tree: proc_info
                    .parent_chain
                    .iter()
                    .map(|entry| WireStringInt {
                        key: entry.path.clone(),
                        value: entry.pid,
                    })
                    .collect(),
            }),
        );
    }

    /// Emit connection event, enqueue warning alerts, and apply ask-timeout policy.
    ///
    /// Inlined at call sites where the compiler can eliminate dead branches
    /// (e.g., when `nolog` is known at compile time).
    #[inline]
    pub(super) async fn apply_default_action_on_client_miss(
        &self,
        request_id: u64,
        proc_info: &ProcessInfo,
        conn: Arc<WireConnection>,
    ) {
        self.emit_connection_event(Arc::clone(&conn), None);
        self.enqueue_connection_warning_alert(conn.as_ref());
        self.enqueue_process_warning_alert(proc_info);
        self.account_miss_and_apply_ask_timeout_policy(request_id)
            .await;
    }

    #[inline]
    pub(super) async fn apply_action(
        &self,
        request_id: u64,
        action: DefaultAction,
        count_stats: bool,
        source: &'static str,
    ) {
        let allow = action.allows();
        self.emit_verdict(
            request_id,
            allow,
            action.rejects(),
            count_stats,
            source,
            None,
        )
        .await;
    }

    pub(super) async fn apply_ask_timeout_policy(&self, request_id: u64, count_stats: bool) {
        let ask_timeout_policy = self.config.get_snapshot().ask_timeout_policy;
        match ask_timeout_policy {
            AskFallbackPolicy::DefaultAction => {
                self.apply_default_action(request_id, count_stats).await
            }
            AskFallbackPolicy::Allow => {
                self.apply_action(
                    request_id,
                    DefaultAction::Allow,
                    count_stats,
                    "ask-timeout-allow",
                )
                .await;
            }
            AskFallbackPolicy::Drop => {
                self.apply_action(
                    request_id,
                    DefaultAction::Deny,
                    count_stats,
                    "ask-timeout-drop",
                )
                .await;
            }
        }
    }

    pub(super) async fn account_miss_and_apply_ask_timeout_policy(&self, request_id: u64) {
        let fallback_policy = self.config.get_snapshot().ask_timeout_policy;
        self.audit
            .emit(AuditEvent::hot(AuditEventKind::VerdictAction(
                VerdictAction::AskTimeoutFallback {
                    request_id,
                    fallback_policy,
                },
            )));
        if self.strict_miss_accounting_enabled() {
            self.stats.on_rule_miss();
            self.apply_ask_timeout_policy(request_id, true).await;
        } else {
            self.stats.on_missed_default_action();
            self.apply_ask_timeout_policy(request_id, false).await;
        }
    }
}

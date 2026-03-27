use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use super::cache_types::RuleMatchCaches;
use super::dispatch::ActiveOperatorDispatch;
use super::matching::{AttemptDerived, AttemptTextNeeds};
use super::{
    rule_record_from_proto, rule_record_now_timestamp, rule_record_to_proto,
};
use crate::models::{
    connection_state::ConnectionAttempt,
    process_state::ProcessInfo,
    rule_match_decision::RuleMatchDecision,
    rule_record::{RuleDuration, RuleOperator, RuleRecord},
};
use anyhow::Result;
use opensnitch_proto::pb;
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

pub(super) struct ActiveRuleCompiled {
    pub(super) name: Arc<str>,
    pub(super) operator: RuleOperator,
    pub(super) decision: RuleMatchDecision,
    pub(super) terminal_on_match: bool,
    pub(super) dispatch: ActiveOperatorDispatch,
}

#[derive(Default)]
pub(super) struct RuleSnapshot {
    pub(super) rules_path: Arc<PathBuf>,
    pub(super) rules: Vec<RuleRecord>,
    pub(super) active_rules: Vec<ActiveRuleCompiled>,
    pub(super) attempt_text_needs: AttemptTextNeeds,
    pub(super) proto_rules: Arc<Vec<pb::Rule>>,
    pub(super) caches: RuleMatchCaches,
}

#[derive(Clone)]
pub struct RuleService {
    snapshot_tx: watch::Sender<Arc<RuleSnapshot>>,
    snapshot_rx: watch::Receiver<Arc<RuleSnapshot>>,
    pub(super) update_lock: Arc<Mutex<()>>,
}

impl Default for RuleService {
    fn default() -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(RuleSnapshot::default()));
        Self {
            snapshot_tx,
            snapshot_rx,
            update_lock: Arc::new(Mutex::new(())),
        }
    }
}

impl RuleService {
    pub(super) fn snapshot(&self) -> Arc<RuleSnapshot> {
        self.snapshot_rx.borrow().clone()
    }

    pub(super) fn publish_snapshot(&self, next: RuleSnapshot) {
        self.snapshot_tx.send_replace(Arc::new(next));
    }

    pub(super) async fn build_and_publish_snapshot(
        &self,
        rules_path: &Path,
        rules: Vec<RuleRecord>,
    ) -> Result<usize> {
        let count = rules.len();
        let caches = Self::build_match_caches(&rules).await?;
        let active_rules = rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                let decision = RuleMatchDecision::from_rule(rule.action, rule.nolog);
                ActiveRuleCompiled {
                    name: Arc::from(rule.name.as_str()),
                    operator: rule.operator.clone(),
                    terminal_on_match: rule.precedence || !decision.allow,
                    decision,
                    dispatch: Self::compile_active_operator_dispatch(&rule.operator, &caches),
                }
            })
            .collect();
        let mut attempt_text_needs = AttemptTextNeeds::default();
        for rule in rules.iter().filter(|rule| rule.enabled) {
            Self::collect_attempt_text_needs(&rule.operator, &mut attempt_text_needs);
        }
        let proto_rules = Arc::new(rules.iter().map(rule_record_to_proto).collect());
        self.publish_snapshot(RuleSnapshot {
            rules_path: Arc::new(rules_path.to_path_buf()),
            rules,
            active_rules,
            attempt_text_needs,
            proto_rules,
            caches,
        });
        Ok(count)
    }

    pub async fn load_path<P>(&self, path: P) -> Result<usize>
    where
        P: AsRef<Path>,
    {
        let _update_guard = self.update_lock.lock().await;
        let path = path.as_ref();
        let (loaded, temporary_rules) = Self::load_rules_from_path(path).await?;
        let loaded_count = self.build_and_publish_snapshot(path, loaded).await?;

        for (rule_name, duration) in temporary_rules {
            self.schedule_temporary_rule(rule_name, duration);
        }

        Ok(loaded_count)
    }

    pub async fn reload(&self) -> Result<usize> {
        let snapshot = self.snapshot();
        self.load_path(snapshot.rules_path.as_path()).await
    }

    /// Reload using synchronous file I/O batched in a single blocking call.
    /// Avoids per-file `spawn_blocking` roundtrips on the inotify fast path.
    pub async fn reload_sync(&self) -> Result<usize> {
        let _update_guard = self.update_lock.lock().await;
        let snapshot = self.snapshot();
        let path = snapshot.rules_path.clone();
        let (loaded, temporary_rules) =
            tokio::task::spawn_blocking(move || Self::load_rules_from_path_sync(&path))
                .await
                .map_err(|e| anyhow::anyhow!("sync rule load join: {e}"))??;
        let loaded_count = self
            .build_and_publish_snapshot(snapshot.rules_path.as_path(), loaded)
            .await?;
        for (rule_name, duration) in temporary_rules {
            self.schedule_temporary_rule(rule_name, duration);
        }
        Ok(loaded_count)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn list_proto(&self) -> Vec<pb::Rule> {
        self.snapshot().proto_rules.as_ref().clone()
    }

    pub fn get_proto_snapshot(&self) -> Arc<Vec<pb::Rule>> {
        let snapshot = self.snapshot();
        Arc::clone(&snapshot.proto_rules)
    }

    pub fn rules_count(&self) -> usize {
        self.snapshot().rules.len()
    }

    fn match_attempt_with_rule_name_in_snapshot(
        snapshot: &RuleSnapshot,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<(RuleMatchDecision, Arc<str>)>> {
        let mut decision = None::<(RuleMatchDecision, Arc<str>)>;
        let derived = AttemptDerived::from_attempt(attempt);
        derived.prewarm(snapshot.attempt_text_needs);

        for rule in snapshot.active_rules.iter() {
            if !Self::operator_matches_compiled_rule(
                rule,
                attempt,
                &derived,
                process,
                dst_host,
                &snapshot.caches,
            ) {
                continue;
            }

            if rule.terminal_on_match {
                return Ok(Some((rule.decision, Arc::clone(&rule.name))));
            }
            decision = Some((rule.decision, Arc::clone(&rule.name)));
        }

        Ok(decision)
    }

    pub fn match_attempt_with_rule_name_sync(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<(RuleMatchDecision, Arc<str>)>> {
        let snapshot = self.snapshot();
        Self::match_attempt_with_rule_name_in_snapshot(
            snapshot.as_ref(),
            attempt,
            process,
            dst_host,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn match_attempt(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<RuleMatchDecision>> {
        Ok(self
            .match_attempt_with_rule_name_sync(attempt, process, dst_host)?
            .map(|(decision, _)| decision))
    }

    pub async fn upsert_from_proto(&self, rule: &pb::Rule) -> Result<RuleMatchDecision> {
        let mut record = rule_record_from_proto(rule);
        let now = rule_record_now_timestamp();
        if record.created_at.is_none() {
            record.created_at = Some(now);
        }
        record.updated_at = Some(now);

        if record.enabled {
            Self::validate_operator(&record.operator)?;
        }

        let decision = RuleMatchDecision::from_rule(record.action, record.nolog);

        if record.duration == RuleDuration::Once {
            return Ok(decision);
        }

        self.upsert_record(record).await?;
        Ok(decision)
    }
}

impl RuleService {
    pub(crate) fn spawn_watch_task(
        &self,
        shutdown: CancellationToken,
    ) -> Box<dyn crate::workers::runtime::control::WorkerControl> {
        super::storage::start_rule_watch_task(self.clone(), shutdown)
    }

    /// Returns `(rule_name, operator_data_path)` for every active rule that carries
    /// a `lists.*` operator with a non-empty `data` directory path.
    ///
    /// Callers use this to cross-reference which rules are backed by subscription-managed
    /// list directories (anything under `<subscription_root>/rules.list.d/`).
    /// The operator tree is walked recursively, so composite `list` rules whose children
    /// are `lists.*` operators are included as well.
    pub fn list_rule_data_paths(&self) -> Vec<(Arc<str>, std::path::PathBuf)> {
        fn collect(op: &crate::models::rule_record::RuleOperator, out: &mut Vec<std::path::PathBuf>) {
            if RuleService::operator_is_lists(&op.type_name, &op.operand) && !op.data.is_empty() {
                out.push(std::path::PathBuf::from(&op.data));
            }
            for child in &op.list {
                collect(child, out);
            }
        }
        let snap = self.snapshot();
        snap.active_rules
            .iter()
            .flat_map(|rule| {
                let mut paths = Vec::new();
                collect(&rule.operator, &mut paths);
                paths.into_iter().map(move |p| (rule.name.clone(), p))
            })
            .collect()
    }
}

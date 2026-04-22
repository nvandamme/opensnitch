use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::unistd::{Uid, User};

use crate::{
    config::Config,
    models::{
        rule_record::{RuleOperator, RuleRecord},
        rule_storage::RuleFile,
    },
    services::{rule::rule_record_now_timestamp, storage::StorageService},
};

use super::{CliOverrides, Daemon};

struct LoadedRuleFile {
    file_path: PathBuf,
    record: RuleRecord,
}

#[derive(Debug, Clone)]
pub(crate) struct OwnerlessRuleMigrationCandidate {
    pub rule_name: String,
    pub file_path: PathBuf,
    pub migrated_record: RuleRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerlessRuleMigrationNote {
    pub rule_name: String,
    pub file_path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct OwnerlessRuleMigrationPlan {
    pub target_uid: u32,
    pub target_username: Option<String>,
    pub rules_path: PathBuf,
    pub eligible: Vec<OwnerlessRuleMigrationCandidate>,
    pub already_scoped: Vec<OwnerlessRuleMigrationNote>,
    pub ambiguous: Vec<OwnerlessRuleMigrationNote>,
    pub conflicting: Vec<OwnerlessRuleMigrationNote>,
}

pub(crate) enum RuleMigrationDecision {
    Eligible(RuleRecord),
    AlreadyScoped(&'static str),
    Ambiguous(&'static str),
    Conflicting(&'static str),
}

impl OwnerlessRuleMigrationPlan {
    fn print_summary(&self, write_mode: bool) {
        println!(
            "ownerless rule migration {} target_uid={} rules_path={}",
            if write_mode { "write" } else { "dry-run" },
            self.target_uid,
            self.rules_path.display()
        );
        if let Some(username) = self.target_username.as_deref() {
            println!("target_username={username}");
        }
        println!("eligible_ownerless={}", self.eligible.len());
        println!("already_scoped={}", self.already_scoped.len());
        println!("ambiguous={}", self.ambiguous.len());
        println!("conflicting={}", self.conflicting.len());

        Self::print_notes(
            "eligible_ownerless",
            self.eligible.iter().map(|entry| {
                (
                    entry.rule_name.as_str(),
                    entry.file_path.as_path(),
                    "owner selector will be injected",
                )
            }),
        );
        Self::print_notes(
            "already_scoped",
            self.already_scoped.iter().map(|entry| {
                (
                    entry.rule_name.as_str(),
                    entry.file_path.as_path(),
                    entry.reason.as_str(),
                )
            }),
        );
        Self::print_notes(
            "ambiguous",
            self.ambiguous.iter().map(|entry| {
                (
                    entry.rule_name.as_str(),
                    entry.file_path.as_path(),
                    entry.reason.as_str(),
                )
            }),
        );
        Self::print_notes(
            "conflicting",
            self.conflicting.iter().map(|entry| {
                (
                    entry.rule_name.as_str(),
                    entry.file_path.as_path(),
                    entry.reason.as_str(),
                )
            }),
        );
    }

    fn print_notes<'a>(label: &str, notes: impl Iterator<Item = (&'a str, &'a Path, &'a str)>) {
        for (rule_name, file_path, reason) in notes {
            println!(
                "{label}: rule={rule_name} file={} reason={reason}",
                file_path.display()
            );
        }
    }
}

impl Daemon {
    pub async fn run_ownerless_rule_migration(cli: CliOverrides) -> Result<()> {
        let owner_uid = cli
            .rule_migration
            .owner_uid
            .as_deref()
            .context("ownerless rule migration requires --migrate-owner-uid <uid>")?
            .parse::<u32>()
            .with_context(|| {
                format!(
                    "invalid --migrate-owner-uid value: {}",
                    cli.rule_migration.owner_uid.as_deref().unwrap_or_default()
                )
            })?;

        let config = Config::load_from_default_locations_with_override(cli.config_file.as_deref())?
            .with_rules_path_override(cli.rules_path.as_deref());
        let plan = load_ownerless_rule_migration_plan(config.rules_path.as_path(), owner_uid)?;
        plan.print_summary(cli.rule_migration.write);

        if !cli.rule_migration.write {
            println!("dry-run only; rerun with --migrate-write to persist eligible rules");
            return Ok(());
        }

        if !plan.ambiguous.is_empty() || !plan.conflicting.is_empty() {
            bail!(
                "ownerless rule migration aborted: ambiguous/conflicting rules require manual review before write mode"
            );
        }

        let storage = StorageService::global();
        for candidate in &plan.eligible {
            let raw = serde_json::to_string_pretty(&RuleFile::from(&candidate.migrated_record))?;
            storage
                .write_bytes_to_path_and_notify("rule", &candidate.file_path, raw.as_bytes())
                .await
                .with_context(|| {
                    format!(
                        "failed to write migrated rule file {}",
                        candidate.file_path.display()
                    )
                })?;
        }

        println!("migrated_rules_written={}", plan.eligible.len());
        Ok(())
    }
}

pub(crate) fn load_ownerless_rule_migration_plan(
    rules_path: &Path,
    target_uid: u32,
) -> Result<OwnerlessRuleMigrationPlan> {
    let loaded_rules = load_rule_files_for_migration(rules_path)?;
    let target_username = User::from_uid(Uid::from_raw(target_uid))
        .ok()
        .flatten()
        .map(|user| user.name);

    let mut plan = OwnerlessRuleMigrationPlan {
        target_uid,
        target_username: target_username.clone(),
        rules_path: rules_path.to_path_buf(),
        eligible: Vec::new(),
        already_scoped: Vec::new(),
        ambiguous: Vec::new(),
        conflicting: Vec::new(),
    };

    for loaded in loaded_rules {
        match classify_rule_for_ownerless_migration(
            &loaded.record,
            target_uid,
            target_username.as_deref(),
        ) {
            RuleMigrationDecision::Eligible(migrated_record) => {
                plan.eligible.push(OwnerlessRuleMigrationCandidate {
                    rule_name: loaded.record.name.clone(),
                    file_path: loaded.file_path,
                    migrated_record,
                });
            }
            RuleMigrationDecision::AlreadyScoped(reason) => {
                plan.already_scoped.push(OwnerlessRuleMigrationNote {
                    rule_name: loaded.record.name,
                    file_path: loaded.file_path,
                    reason: reason.to_string(),
                });
            }
            RuleMigrationDecision::Ambiguous(reason) => {
                plan.ambiguous.push(OwnerlessRuleMigrationNote {
                    rule_name: loaded.record.name,
                    file_path: loaded.file_path,
                    reason: reason.to_string(),
                });
            }
            RuleMigrationDecision::Conflicting(reason) => {
                plan.conflicting.push(OwnerlessRuleMigrationNote {
                    rule_name: loaded.record.name,
                    file_path: loaded.file_path,
                    reason: reason.to_string(),
                });
            }
        }
    }

    Ok(plan)
}

fn load_rule_files_for_migration(rules_path: &Path) -> Result<Vec<LoadedRuleFile>> {
    let entries = std::fs::read_dir(rules_path)
        .with_context(|| format!("failed to read rules directory {}", rules_path.display()))?;
    let mut json_paths: Vec<PathBuf> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("json")).then_some(path)
        })
        .collect();
    json_paths.sort();

    let mut loaded = Vec::new();
    for file_path in json_paths {
        let contents = std::fs::read_to_string(&file_path)
            .with_context(|| format!("failed to read rule file {}", file_path.display()))?;
        let rule_file: RuleFile = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse rule file {}", file_path.display()))?;
        loaded.push(LoadedRuleFile {
            file_path,
            record: RuleRecord::from(rule_file),
        });
    }
    Ok(loaded)
}

pub(crate) fn classify_rule_for_ownerless_migration(
    rule: &RuleRecord,
    target_uid: u32,
    target_username: Option<&str>,
) -> RuleMigrationDecision {
    if rule.precedence {
        return RuleMigrationDecision::Ambiguous(
            "precedence rule requires manual review before ownership migration",
        );
    }

    if operator_is_empty(&rule.operator) {
        return RuleMigrationDecision::Ambiguous(
            "rule has no operator payload to scope to an owner",
        );
    }

    if !operator_has_any_operand(&rule.operator) {
        return RuleMigrationDecision::Ambiguous(
            "rule operator payload has no operand; migration requires explicit operand semantics",
        );
    }

    let mut saw_owner_match = false;
    if let Err(reason) = rule_operator_owner_scope_conflicts(
        &rule.operator,
        target_uid,
        target_username,
        &mut saw_owner_match,
    ) {
        return RuleMigrationDecision::Conflicting(reason);
    }

    if saw_owner_match {
        return RuleMigrationDecision::AlreadyScoped(
            "rule already carries an owner selector matching the migration target",
        );
    }

    let mut migrated_record = rule.clone();
    inject_rule_owner_uid_scope(&mut migrated_record, target_uid);
    migrated_record.updated_at = Some(rule_record_now_timestamp());
    RuleMigrationDecision::Eligible(migrated_record)
}

fn operator_is_empty(operator: &RuleOperator) -> bool {
    operator.type_name.trim().is_empty()
        && operator.operand.trim().is_empty()
        && operator.data.trim().is_empty()
        && operator.list.is_empty()
}

fn operator_has_any_operand(operator: &RuleOperator) -> bool {
    if !operator.operand.trim().is_empty() {
        return true;
    }
    operator.list.iter().any(operator_has_any_operand)
}

fn rule_operator_owner_scope_conflicts(
    operator: &RuleOperator,
    target_uid: u32,
    target_username: Option<&str>,
    saw_owner_match: &mut bool,
) -> std::result::Result<(), &'static str> {
    if operator.operand.eq_ignore_ascii_case("user.id") {
        let Ok(candidate_uid) = operator.data.trim().parse::<u32>() else {
            return Err("rule contains an invalid existing user.id owner selector");
        };
        if candidate_uid != target_uid {
            return Err("rule already carries a conflicting user.id owner selector");
        }
        *saw_owner_match = true;
    }

    if operator.operand.eq_ignore_ascii_case("user.name") {
        let Some(target_username) = target_username else {
            return Err(
                "rule uses user.name owner scope but target UID has no resolvable username",
            );
        };
        if operator.data.trim() != target_username {
            return Err("rule already carries a conflicting user.name owner selector");
        }
        *saw_owner_match = true;
    }

    for nested in &operator.list {
        rule_operator_owner_scope_conflicts(nested, target_uid, target_username, saw_owner_match)?;
    }

    Ok(())
}

fn inject_rule_owner_uid_scope(rule: &mut RuleRecord, owner_uid: u32) {
    let existing_operator = std::mem::take(&mut rule.operator);
    let owner_operator = RuleOperator {
        type_name: "simple".to_string(),
        operand: "user.id".to_string(),
        data: owner_uid.to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    rule.operator = RuleOperator {
        type_name: "list".to_string(),
        operand: String::new(),
        data: String::new(),
        sensitive: false,
        scope: None,
        list: vec![existing_operator, owner_operator],
    };
}

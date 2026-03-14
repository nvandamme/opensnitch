use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use opensnitch_proto::pb;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::models::{
    connection::ConnectionAttempt,
    process::ProcessInfo,
    rule::{RuleRecord, RuleAction, RuleDuration, RuleOperator},
};

#[derive(Clone, Default)]
pub struct RuleService {
    rules: Arc<RwLock<Vec<RuleRecord>>>,
    rules_path: Arc<RwLock<PathBuf>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct DiskOperator {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    operand: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    sensitive: bool,
    #[serde(default)]
    list: Vec<DiskOperator>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DiskRule {
    #[serde(default)]
    created: String,
    #[serde(default)]
    updated: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    duration: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    precedence: bool,
    #[serde(default)]
    nolog: bool,
    #[serde(default)]
    operator: DiskOperator,
}

impl RuleService {
    pub async fn load_path<P>(&self, path: P) -> Result<usize>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_path_buf();
        let mut loaded = Vec::new();

        if path.exists() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("failed to read rules directory {}", path.display()))?
            {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }

                let raw_rule = fs::read_to_string(&file_path)
                    .with_context(|| format!("failed to read rule file {}", file_path.display()))?;
                let disk_rule: DiskRule = serde_json::from_str(&raw_rule)
                    .with_context(|| format!("failed to parse rule file {}", file_path.display()))?;
                loaded.push(rule_from_disk(disk_rule));
            }

            loaded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        }

        *self.rules.write().await = loaded;
        *self.rules_path.write().await = path;

        Ok(self.rules.read().await.len())
    }

    pub async fn reload(&self) -> Result<usize> {
        let path = self.rules_path.read().await.clone();
        self.load_path(path).await
    }

    pub async fn list_proto(&self) -> Vec<pb::Rule> {
        self.rules.read().await.iter().map(RuleRecord::to_proto).collect()
    }

    pub async fn match_attempt(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<bool>> {
        let rules = self.rules.read().await;
        let mut decision = None;

        for rule in rules.iter().filter(|rule| rule.enabled) {
            if !matches_rule(rule, attempt, process, dst_host) {
                continue;
            }

            let allow = rule.action.allows();
            if rule.precedence {
                return Ok(Some(allow));
            }
            decision = Some(allow);
        }

        Ok(decision)
    }

    pub async fn upsert_from_proto(&self, rule: &pb::Rule) -> Result<bool> {
        let mut record = RuleRecord::from_proto(rule);
        let now = RuleRecord::now_timestamp();
        if record.created_at.is_none() {
            record.created_at = Some(now);
        }
        record.updated_at = Some(now);

        let allow = record.action.allows();
        self.upsert_record(record).await?;
        Ok(allow)
    }

    pub async fn delete_by_name(&self, rule_name: &str) -> Result<()> {
        self.rules.write().await.retain(|rule| rule.name != rule_name);

        let path = self.rules_path.read().await.clone();
        let file_path = rule_file_path(&path, rule_name);
        if file_path.exists() {
            fs::remove_file(file_path)?;
        }

        Ok(())
    }

    async fn upsert_record(&self, record: RuleRecord) -> Result<()> {
        let mut rules = self.rules.write().await;
        if let Some(existing) = rules.iter_mut().find(|current| current.name == record.name) {
            *existing = record.clone();
        } else {
            rules.push(record.clone());
            rules.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        }
        drop(rules);

        if record.duration.persists_to_disk() {
            let path = self.rules_path.read().await.clone();
            fs::create_dir_all(&path)?;
            let file_path = rule_file_path(&path, &record.name);
            let raw = serde_json::to_string_pretty(&rule_to_disk(&record))?;
            fs::write(file_path, raw)?;
        }

        Ok(())
    }
}

fn rule_from_disk(rule: DiskRule) -> RuleRecord {
    RuleRecord {
        created_at: RuleRecord::parse_timestamp(&rule.created),
        updated_at: RuleRecord::parse_timestamp(&rule.updated),
        name: rule.name,
        description: rule.description,
        action: RuleAction::from_name(&rule.action),
        duration: RuleDuration::from_name(&rule.duration),
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        operator: disk_operator_to_model(rule.operator),
    }
}

fn rule_to_disk(rule: &RuleRecord) -> DiskRule {
    DiskRule {
        created: rule
            .created_at
            .map(RuleRecord::format_timestamp)
            .unwrap_or_default(),
        updated: rule
            .updated_at
            .map(RuleRecord::format_timestamp)
            .unwrap_or_default(),
        name: rule.name.clone(),
        description: rule.description.clone(),
        action: rule.action.as_str().to_string(),
        duration: rule.duration.as_str().to_string(),
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        operator: model_operator_to_disk(&rule.operator),
    }
}

fn disk_operator_to_model(operator: DiskOperator) -> RuleOperator {
    RuleOperator {
        type_name: operator.r#type,
        operand: operator.operand,
        data: operator.data,
        sensitive: operator.sensitive,
        list: operator
            .list
            .into_iter()
            .map(disk_operator_to_model)
            .collect(),
    }
}

fn model_operator_to_disk(operator: &RuleOperator) -> DiskOperator {
    DiskOperator {
        r#type: operator.type_name.clone(),
        operand: operator.operand.clone(),
        data: operator.data.clone(),
        sensitive: operator.sensitive,
        list: operator.list.iter().map(model_operator_to_disk).collect(),
    }
}

fn rule_file_path(path: &Path, rule_name: &str) -> PathBuf {
    path.join(format!("{rule_name}.json"))
}

fn matches_rule(
    rule: &RuleRecord,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    dst_host: Option<&str>,
) -> bool {
    matches_operator(&rule.operator, attempt, process, dst_host)
}

fn matches_operator(
    operator: &RuleOperator,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    dst_host: Option<&str>,
) -> bool {
    if operator.operand == "true" {
        return true;
    }

    if operator.operand == "list" || operator.type_name.eq_ignore_ascii_case("list") {
        return operator
            .list
            .iter()
            .all(|item| matches_operator(item, attempt, process, dst_host));
    }

    let Some(candidate) = operand_value(operator.operand.as_str(), attempt, process, dst_host) else {
        return false;
    };

    if operator.type_name.eq_ignore_ascii_case("regexp") {
        let pattern = if operator.sensitive {
            operator.data.clone()
        } else {
            format!("(?i:{})", operator.data)
        };
        return Regex::new(&pattern)
            .map(|regex| regex.is_match(&candidate))
            .unwrap_or(false);
    }

    compare_value(&candidate, &operator.data, operator.sensitive)
}

fn operand_value(
    operand: &str,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    dst_host: Option<&str>,
) -> Option<String> {
    match operand {
        "process.path" => Some(process.path.clone()),
        "process.command" => Some(process.args.join(" ")),
        "process.id" => Some(process.pid.to_string()),
        "user.id" => Some(attempt.uid.to_string()),
        "dest.ip" => Some(attempt.dst_ip.clone()),
        "dest.host" => dst_host.map(ToOwned::to_owned),
        "dest.port" => Some(attempt.dst_port.to_string()),
        "source.ip" => Some(attempt.src_ip.clone()),
        "source.port" => Some(attempt.src_port.to_string()),
        "protocol" => Some(match attempt.protocol {
            crate::models::connection::TransportProtocol::Tcp => "tcp".to_string(),
            crate::models::connection::TransportProtocol::Udp => "udp".to_string(),
        }),
        _ => None,
    }
}

fn compare_value(candidate: &str, expected: &str, sensitive: bool) -> bool {
    if sensitive {
        candidate == expected
    } else {
        candidate.eq_ignore_ascii_case(expected)
    }
}

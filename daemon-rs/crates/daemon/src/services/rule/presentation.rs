use std::{collections::BTreeMap, time::SystemTime};

use transport_wire_core::{WireRule, WireRuleOperator};

use super::RuleService;

impl RuleService {
    pub(crate) fn format_rule_operator(operator: &WireRuleOperator) -> String {
        if !operator.list.is_empty() {
            let mut out = String::new();
            for (idx, item) in operator.list.iter().enumerate() {
                if idx > 0 {
                    out.push_str(" and ");
                }
                out.push_str(&Self::format_rule_operator(item));
            }
            return out;
        }

        if operator.operand.is_empty() {
            return operator.data.clone();
        }

        if operator.data.is_empty() {
            return operator.operand.clone();
        }

        format!("{} is '{}'", operator.operand, operator.data)
    }

    pub(crate) fn format_deleted_rule(rule: &WireRule) -> String {
        let state = if rule.enabled { "Enabled" } else { "Disabled" };
        let condition = rule
            .operator
            .as_ref()
            .map(Self::format_rule_operator)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "true".to_string());
        format!(
            "Delete() rule: [{}] {}: if({}){{ {} {} }}",
            state, rule.name, condition, rule.action, rule.duration
        )
    }

    pub(crate) fn diff_rule_files(
        previous: &BTreeMap<String, Option<SystemTime>>,
        current: &BTreeMap<String, Option<SystemTime>>,
    ) -> Vec<String> {
        let mut changed = Vec::new();
        for (name, mtime) in previous {
            match current.get(name) {
                None => changed.push(name.clone()),
                Some(cur) if cur != mtime => changed.push(name.clone()),
                _ => {}
            }
        }
        for name in current.keys() {
            if !previous.contains_key(name) {
                changed.push(name.clone());
            }
        }
        changed.sort();
        changed.dedup();
        changed
    }

    pub(crate) fn removed_rule_files(
        previous: &BTreeMap<String, Option<SystemTime>>,
        current: &BTreeMap<String, Option<SystemTime>>,
    ) -> Vec<String> {
        previous
            .keys()
            .filter(|name| !current.contains_key(*name))
            .cloned()
            .collect()
    }
}

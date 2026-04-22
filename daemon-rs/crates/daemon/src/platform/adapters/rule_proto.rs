#![cfg(test)]

use transport_wire_core::{WireRule, WireRuleOperator};

use crate::models::rule_record::{RuleAction, RuleDuration, RuleOperator, RuleRecord};
use crate::utils::name_parsing::case_folded;
use time::OffsetDateTime;

pub(crate) fn rule_record_from_wire(rule: &WireRule) -> RuleRecord {
    RuleRecord {
        created_at: OffsetDateTime::from_unix_timestamp(rule.created).ok(),
        updated_at: None,
        name: rule.name.clone(),
        description: rule.description.clone(),
        action: RuleAction::from_name(&rule.action),
        duration: RuleDuration::from_name(&rule.duration),
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        operator: rule_operator_from_wire(rule.operator.as_ref()),
    }
}

fn rule_operator_from_wire(operator: Option<&WireRuleOperator>) -> RuleOperator {
    let Some(operator) = operator else {
        return RuleOperator::default();
    };

    let mut parsed = RuleOperator {
        type_name: operator.type_name.clone(),
        operand: operator.operand.clone(),
        data: operator.data.clone(),
        sensitive: operator.sensitive,
        scope: None,
        list: operator
            .list
            .iter()
            .map(|item| rule_operator_from_wire(Some(item)))
            .collect(),
    };

    if case_folded(&parsed.type_name) == "list" {
        parsed.data.clear();
    }

    parsed
}

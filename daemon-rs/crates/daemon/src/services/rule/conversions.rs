use crate::models::{
    rule_record::{RuleAction, RuleDuration, RuleOperator, RuleRecord},
    rule_storage::{RuleFile, RuleFileOperator},
};
use crate::utils::name_parsing::case_folded;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use transport_wire_core::{WireRule, WireRuleOperator};

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

pub(crate) fn wire_rule_from_record(rule: &RuleRecord) -> WireRule {
    WireRule {
        created: rule
            .created_at
            .map(|value| value.unix_timestamp())
            .unwrap_or(0),
        name: rule.name.clone(),
        description: rule.description.clone(),
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        action: rule.action.as_str().to_string(),
        duration: rule.duration.as_str().to_string(),
        operator: Some(wire_operator_from_rule_operator(&rule.operator)),
    }
}

pub(crate) fn rule_record_now_timestamp() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) fn parse_rule_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

pub(crate) fn format_rule_timestamp(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
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

fn wire_operator_from_rule_operator(operator: &RuleOperator) -> WireRuleOperator {
    WireRuleOperator {
        type_name: operator.type_name.clone(),
        operand: operator.operand.clone(),
        data: operator.data.clone(),
        sensitive: operator.sensitive,
        list: operator
            .list
            .iter()
            .map(wire_operator_from_rule_operator)
            .collect(),
    }
}

impl From<RuleFile> for RuleRecord {
    fn from(rule: RuleFile) -> Self {
        Self {
            created_at: parse_rule_timestamp(&rule.created),
            updated_at: parse_rule_timestamp(&rule.updated),
            name: rule.name,
            description: rule.description,
            action: RuleAction::from_name(&rule.action),
            duration: RuleDuration::from_name(&rule.duration),
            enabled: rule.enabled,
            precedence: rule.precedence,
            nolog: rule.nolog,
            operator: RuleOperator::from(rule.operator),
        }
    }
}

impl From<&RuleRecord> for RuleFile {
    fn from(rule: &RuleRecord) -> Self {
        Self {
            created: rule
                .created_at
                .map(format_rule_timestamp)
                .unwrap_or_default(),
            updated: rule
                .updated_at
                .map(format_rule_timestamp)
                .unwrap_or_default(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            action: rule.action.as_str().to_string(),
            duration: rule.duration.as_str().to_string(),
            enabled: rule.enabled,
            precedence: rule.precedence,
            nolog: rule.nolog,
            operator: RuleFileOperator::from(&rule.operator),
        }
    }
}

impl From<RuleFileOperator> for RuleOperator {
    fn from(operator: RuleFileOperator) -> Self {
        let mut operator = operator;
        if case_folded(&operator.r#type) == "list"
            && operator.list.is_empty()
            && !operator.data.trim().is_empty()
            && let Ok(decoded) = serde_json::from_str::<Vec<RuleFileOperator>>(&operator.data)
        {
            operator.list = decoded;
            operator.data.clear();
        }

        Self {
            type_name: operator.r#type,
            operand: operator.operand,
            data: operator.data,
            sensitive: operator.sensitive,
            scope: operator.scope.and_then(|scope| {
                if scope.trim().is_empty() {
                    None
                } else {
                    Some(scope)
                }
            }),
            list: operator.list.into_iter().map(RuleOperator::from).collect(),
        }
    }
}

impl From<&RuleOperator> for RuleFileOperator {
    fn from(operator: &RuleOperator) -> Self {
        Self {
            r#type: operator.type_name.clone(),
            operand: operator.operand.clone(),
            data: operator.data.clone(),
            sensitive: operator.sensitive,
            scope: operator.scope.clone(),
            list: operator.list.iter().map(RuleFileOperator::from).collect(),
        }
    }
}

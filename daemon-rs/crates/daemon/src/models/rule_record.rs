use opensnitch_proto::pb;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::utils::name_parsing::{ParseFromName, normalized_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    Reject,
}

impl RuleAction {
    pub fn from_name(name: &str) -> Self {
        <Self as ParseFromName>::parse_from_name(name)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        }
    }

    pub fn allows(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn rejects(self) -> bool {
        matches!(self, Self::Reject)
    }
}

impl ParseFromName for RuleAction {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "reject" => Self::Reject,
            "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleDuration {
    Once,
    UntilRestart,
    Permanent,
    Temporary(String),
}

impl RuleDuration {
    pub fn from_name(name: &str) -> Self {
        <Self as ParseFromName>::parse_from_name(name)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Once => "once",
            Self::UntilRestart => "until restart",
            Self::Permanent => "always",
            Self::Temporary(value) => value.as_str(),
        }
    }

    pub fn persists_to_disk(&self) -> bool {
        matches!(self, Self::Permanent)
    }

    pub fn temporary_spec(&self) -> Option<&str> {
        match self {
            Self::Temporary(value) => Some(value.as_str()),
            _ => None,
        }
    }
}

impl ParseFromName for RuleDuration {
    fn parse_from_name(name: &str) -> Self {
        let normalized = name.trim();
        match normalized_name(normalized).as_str() {
            "always" | "permanent" => Self::Permanent,
            "until restart" | "restart" => Self::UntilRestart,
            "once" => Self::Once,
            _ if normalized.is_empty() => Self::Once,
            _ => Self::Temporary(normalized.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleOperator {
    pub type_name: String,
    pub operand: String,
    pub data: String,
    pub sensitive: bool,
    pub list: Vec<RuleOperator>,
}

impl RuleOperator {
    pub fn from_proto(operator: Option<&pb::Operator>) -> Self {
        let Some(operator) = operator else {
            return Self::default();
        };

        let mut parsed = Self {
            type_name: operator.r#type.clone(),
            operand: operator.operand.clone(),
            data: operator.data.clone(),
            sensitive: operator.sensitive,
            list: operator
                .list
                .iter()
                .map(|item| Self::from_proto(Some(item)))
                .collect(),
        };

        if parsed.type_name.eq_ignore_ascii_case("list") {
            parsed.data.clear();
        }

        parsed
    }

    pub fn to_proto(&self) -> pb::Operator {
        pb::Operator {
            r#type: self.type_name.clone(),
            operand: self.operand.clone(),
            data: self.data.clone(),
            sensitive: self.sensitive,
            list: self.list.iter().map(Self::to_proto).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleRecord {
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
    pub name: String,
    pub description: String,
    pub action: RuleAction,
    pub duration: RuleDuration,
    pub enabled: bool,
    pub precedence: bool,
    pub nolog: bool,
    pub operator: RuleOperator,
}

impl RuleRecord {
    pub fn from_proto(rule: &pb::Rule) -> Self {
        Self {
            created_at: OffsetDateTime::from_unix_timestamp(rule.created).ok(),
            updated_at: None,
            name: rule.name.clone(),
            description: rule.description.clone(),
            action: RuleAction::from_name(&rule.action),
            duration: RuleDuration::from_name(&rule.duration),
            enabled: rule.enabled,
            precedence: rule.precedence,
            nolog: rule.nolog,
            operator: RuleOperator::from_proto(rule.operator.as_ref()),
        }
    }

    pub fn to_proto(&self) -> pb::Rule {
        pb::Rule {
            created: self
                .created_at
                .map(|value| value.unix_timestamp())
                .unwrap_or(0),
            name: self.name.clone(),
            description: self.description.clone(),
            enabled: self.enabled,
            precedence: self.precedence,
            nolog: self.nolog,
            action: self.action.as_str().to_string(),
            duration: self.duration.as_str().to_string(),
            operator: Some(self.operator.to_proto()),
        }
    }

    pub fn now_timestamp() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    pub fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
        OffsetDateTime::parse(value, &Rfc3339).ok()
    }

    pub fn format_timestamp(value: OffsetDateTime) -> String {
        value
            .format(&Rfc3339)
            .unwrap_or_else(|_| value.unix_timestamp().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{RuleAction, RuleDuration, RuleRecord};
    use opensnitch_proto::pb;

    #[test]
    fn from_proto_maps_core_fields_like_create_invariants() {
        let proto = pb::Rule {
            created: 1_700_000_000,
            name: "000-test-name".to_string(),
            description: "rule description 000".to_string(),
            enabled: true,
            precedence: false,
            nolog: false,
            action: "allow".to_string(),
            duration: "once".to_string(),
            operator: Some(pb::Operator {
                r#type: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
        };

        let record = RuleRecord::from_proto(&proto);
        assert_eq!(record.name, "000-test-name");
        assert_eq!(record.description, "rule description 000");
        assert!(record.enabled);
        assert!(!record.precedence);
        assert!(!record.nolog);
        assert_eq!(record.action, RuleAction::Allow);
        assert_eq!(record.duration, RuleDuration::Once);
        assert!(record.created_at.is_some());
    }

    #[test]
    fn from_proto_list_operator_clears_data_and_keeps_expanded_list() {
        let proto = pb::Rule {
            name: "000-test-serializer-list".to_string(),
            action: "allow".to_string(),
            duration: "once".to_string(),
            enabled: true,
            operator: Some(pb::Operator {
                r#type: "list".to_string(),
                operand: "list".to_string(),
                data: "[\"test\":true]".to_string(),
                sensitive: false,
                list: vec![
                    pb::Operator {
                        r#type: "simple".to_string(),
                        operand: "process.path".to_string(),
                        data: "/path/x".to_string(),
                        sensitive: false,
                        list: Vec::new(),
                    },
                    pb::Operator {
                        r#type: "simple".to_string(),
                        operand: "dest.port".to_string(),
                        data: "23".to_string(),
                        sensitive: false,
                        list: Vec::new(),
                    },
                ],
            }),
            ..Default::default()
        };

        let record = RuleRecord::from_proto(&proto);
        assert_eq!(record.operator.type_name, "list");
        assert_eq!(record.operator.operand, "list");
        assert_eq!(record.operator.data, "");
        assert_eq!(record.operator.list.len(), 2);
        assert_eq!(record.operator.list[0].type_name, "simple");
        assert_eq!(record.operator.list[0].operand, "process.path");
        assert_eq!(record.operator.list[0].data, "/path/x");
        assert_eq!(record.operator.list[1].type_name, "simple");
        assert_eq!(record.operator.list[1].operand, "dest.port");
        assert_eq!(record.operator.list[1].data, "23");
    }
}

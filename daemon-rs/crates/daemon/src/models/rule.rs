use opensnitch_proto::pb;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
}

impl RuleAction {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "deny" | "reject" => Self::Deny,
            _ => Self::Allow,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    pub fn allows(self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDuration {
    Once,
    UntilRestart,
    Permanent,
}

impl RuleDuration {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "always" | "permanent" => Self::Permanent,
            "until restart" | "restart" => Self::UntilRestart,
            _ => Self::Once,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::UntilRestart => "until restart",
            Self::Permanent => "always",
        }
    }

    pub fn persists_to_disk(self) -> bool {
        matches!(self, Self::Permanent)
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

        Self {
            type_name: operator.r#type.clone(),
            operand: operator.operand.clone(),
            data: operator.data.clone(),
            sensitive: operator.sensitive,
            list: operator
                .list
                .iter()
                .map(|item| Self::from_proto(Some(item)))
                .collect(),
        }
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
            created: self.created_at.map(|value| value.unix_timestamp()).unwrap_or(0),
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

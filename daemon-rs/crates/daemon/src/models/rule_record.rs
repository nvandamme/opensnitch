use time::OffsetDateTime;

use crate::utils::name_parsing::normalized_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleAction {
    #[default]
    Allow,
    Deny,
    Reject,
}

impl RuleAction {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "reject" => Self::Reject,
            "drop" | "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RuleDuration {
    #[default]
    Once,
    UntilRestart,
    Permanent,
    Temporary(String),
}

impl RuleDuration {
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

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Once => "once",
            Self::UntilRestart => "until restart",
            Self::Permanent => "always",
            Self::Temporary(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleOperator {
    pub type_name: String,
    pub operand: String,
    pub data: String,
    pub sensitive: bool,
    pub scope: Option<String>,
    pub list: Vec<RuleOperator>,
}

impl RuleOperator {
    /// Returns `true` when all fields are empty — i.e. no operator was provided
    /// (equivalent to `pb::Rule.operator` being `None` on the wire).
    pub fn is_empty(&self) -> bool {
        self.type_name.is_empty()
            && self.operand.is_empty()
            && self.data.is_empty()
            && self.list.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
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

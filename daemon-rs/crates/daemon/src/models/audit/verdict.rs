use crate::config::AskFallbackPolicy;
use crate::models::rule_record::RuleAction;

/// Verdict domain runtime actions (decision outcomes and queue observations).
#[derive(Debug, Clone, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum VerdictAction {
    AskTimeoutFallback {
        request_id: u64,
        fallback_policy: AskFallbackPolicy,
    },
    AskRuleRulePersisted {
        request_id: u64,
        rule_name: String,
        action: RuleAction,
    },
    VerdictQueueBackpressure {
        request_id: u64,
        source: VerdictSource,
    },
}

/// Typed source label for verdict backpressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Intentional audit vocabulary API surface; emit sites vary by runtime profile.
#[allow(dead_code)]
pub enum VerdictSource {
    DefaultAction,
    AskTimeoutAllow,
    AskTimeoutDrop,
    SelfConnection,
    RuntimeRule,
    Other,
}

impl VerdictSource {
    pub fn from_verdict_source(source: &str) -> Self {
        match source {
            "default-action" => Self::DefaultAction,
            "ask-timeout-allow" => Self::AskTimeoutAllow,
            "ask-timeout-drop" => Self::AskTimeoutDrop,
            "self-connection" => Self::SelfConnection,
            "runtime-rule" => Self::RuntimeRule,
            _ => Self::Other,
        }
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::DefaultAction => "default-action",
            Self::AskTimeoutAllow => "ask-timeout-allow",
            Self::AskTimeoutDrop => "ask-timeout-drop",
            Self::SelfConnection => "self-connection",
            Self::RuntimeRule => "runtime-rule",
            Self::Other => "other",
        }
    }
}

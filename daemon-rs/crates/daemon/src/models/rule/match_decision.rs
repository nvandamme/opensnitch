use crate::models::rule::record::RuleAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMatchSummary {
    pub action: &'static str,
    pub nolog: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMatchDecision {
    pub allow: bool,
    pub reject: bool,
    pub nolog: bool,
}

impl RuleMatchDecision {
    pub fn from_rule(action: RuleAction, nolog: bool) -> Self {
        Self {
            allow: matches!(action, RuleAction::Allow),
            reject: matches!(action, RuleAction::Reject),
            nolog,
        }
    }

    pub(crate) fn to_summary(self) -> RuleMatchSummary {
        RuleMatchSummary {
            action: if self.allow {
                "allow"
            } else if self.reject {
                "reject"
            } else {
                "deny"
            },
            nolog: self.nolog,
        }
    }
}

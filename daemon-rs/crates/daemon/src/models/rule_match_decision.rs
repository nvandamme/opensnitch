use opensnitch_proto::pb;

use crate::models::rule_record::RuleAction;

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

    pub(crate) fn to_summary_rule(self) -> pb::Rule {
        pb::Rule {
            created: 0,
            name: "runtime-match".to_owned(),
            description: "matched existing runtime rule".to_owned(),
            enabled: true,
            precedence: false,
            nolog: self.nolog,
            action: if self.allow {
                "allow".to_owned()
            } else if self.reject {
                "reject".to_owned()
            } else {
                "deny".to_owned()
            },
            duration: "always".to_owned(),
            operator: None,
        }
    }
}
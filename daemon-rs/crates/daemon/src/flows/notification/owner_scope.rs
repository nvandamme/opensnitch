use super::notification::NotificationFlow;
use crate::models::{
    firewall_config::{
        FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement, FirewallStatementValue,
    },
    rule_record::{RuleOperator, RuleRecord},
};

impl NotificationFlow {
    pub(super) fn operator_matches_owner_scope(
        operator: &RuleOperator,
        owner_uid: u32,
        owner_username: Option<&str>,
        owner_group_gids: &[u32],
        saw_owner_match: &mut bool,
    ) -> bool {
        if operator.operand.eq_ignore_ascii_case("user.id") {
            let Some(uid) = operator.data.trim().parse::<u32>().ok() else {
                return false;
            };
            if uid != owner_uid {
                return false;
            }
            *saw_owner_match = true;
        }

        if operator.operand.eq_ignore_ascii_case("user.name") {
            let Some(owner_username) = owner_username else {
                return false;
            };
            if operator.data.trim() != owner_username {
                return false;
            }
            *saw_owner_match = true;
        }

        if operator.operand.eq_ignore_ascii_case("user.gid") {
            let Some(candidate_gid) = operator.data.trim().parse::<u32>().ok() else {
                return false;
            };
            if !owner_group_gids.contains(&candidate_gid) {
                return false;
            }
            *saw_owner_match = true;
        }

        operator.list.iter().all(|nested| {
            Self::operator_matches_owner_scope(
                nested,
                owner_uid,
                owner_username,
                owner_group_gids,
                saw_owner_match,
            )
        })
    }

    pub(super) fn rule_matches_owner_scope(rule: &RuleRecord, owner_uid: u32) -> bool {
        if rule.precedence {
            return false;
        }

        let operator = &rule.operator;
        if operator.is_empty() {
            return false;
        }

        let owner_username = Self::username_for_uid(owner_uid);
        let owner_group_gids = Self::group_memberships_for_uid(owner_uid);
        let mut saw_owner_match = false;
        Self::operator_matches_owner_scope(
            operator,
            owner_uid,
            owner_username.as_deref(),
            owner_group_gids.as_slice(),
            &mut saw_owner_match,
        ) && saw_owner_match
    }

    pub(super) fn operator_has_any_operand(operator: &RuleOperator) -> bool {
        if !operator.operand.trim().is_empty() {
            return true;
        }
        operator.list.iter().any(Self::operator_has_any_operand)
    }

    pub(super) fn rule_has_operand_semantics(rule: &RuleRecord) -> bool {
        let operator = &rule.operator;
        if operator.is_empty() {
            return false;
        }
        Self::operator_has_any_operand(operator)
    }

    pub(super) fn firewall_parameters_match_owner_scope(
        parameters: &str,
        owner_uid: u32,
        owner_group_gids: &[u32],
    ) -> bool {
        let uid_text = owner_uid.to_string();
        let tokens: Vec<&str> = parameters.split_ascii_whitespace().collect();
        for index in 0..tokens.len() {
            if tokens[index] == "--uid-owner" && tokens.get(index + 1) == Some(&uid_text.as_str()) {
                return true;
            }
            if tokens[index] == "--gid-owner"
                && let Some(candidate_gid) =
                    tokens.get(index + 1).and_then(|g| g.parse::<u32>().ok())
                && owner_group_gids.contains(&candidate_gid)
            {
                return true;
            }
            if tokens[index].eq_ignore_ascii_case("skuid") {
                if tokens.get(index + 1) == Some(&uid_text.as_str()) {
                    return true;
                }
                if matches!(tokens.get(index + 1), Some(&"=") | Some(&"=="))
                    && tokens.get(index + 2) == Some(&uid_text.as_str())
                {
                    return true;
                }
            }
            if tokens[index].eq_ignore_ascii_case("skgid") {
                if let Some(candidate_gid) =
                    tokens.get(index + 1).and_then(|g| g.parse::<u32>().ok())
                    && owner_group_gids.contains(&candidate_gid)
                {
                    return true;
                }
                if matches!(tokens.get(index + 1), Some(&"=") | Some(&"=="))
                    && let Some(candidate_gid) =
                        tokens.get(index + 2).and_then(|g| g.parse::<u32>().ok())
                    && owner_group_gids.contains(&candidate_gid)
                {
                    return true;
                }
            }
        }
        false
    }

    pub(super) fn firewall_rule_matches_owner_scope(
        rule: &FirewallRule,
        owner_uid: u32,
        owner_group_gids: &[u32],
    ) -> bool {
        if Self::firewall_parameters_match_owner_scope(
            rule.parameters.as_str(),
            owner_uid,
            owner_group_gids,
        ) {
            return true;
        }

        let uid_text = owner_uid.to_string();
        let gids_text: Vec<String> = owner_group_gids.iter().map(ToString::to_string).collect();
        rule.expressions.iter().any(|expression| {
            let Some(statement) = expression.statement.as_ref() else {
                return false;
            };
            if !statement.name.eq_ignore_ascii_case("meta") {
                return false;
            }
            statement.values.iter().any(|value| {
                (value.key.eq_ignore_ascii_case("skuid") && value.value.trim() == uid_text)
                    || (value.key.eq_ignore_ascii_case("skgid")
                        && gids_text.iter().any(|gid| gid == value.value.trim()))
            })
        })
    }

    pub(super) fn firewall_expressions_have_conflicting_owner_scope(
        expressions: &[FirewallExpression],
        owner_uid: u32,
        owner_group_gids: &[u32],
    ) -> bool {
        let uid_text = owner_uid.to_string();
        expressions.iter().any(|expression| {
            let Some(statement) = expression.statement.as_ref() else {
                return false;
            };
            statement.name.eq_ignore_ascii_case("meta")
                && statement.values.iter().any(|value| {
                    (value.key.eq_ignore_ascii_case("skuid") && value.value.trim() != uid_text)
                        || (value.key.eq_ignore_ascii_case("skgid")
                            && value
                                .value
                                .trim()
                                .parse::<u32>()
                                .ok()
                                .is_some_and(|gid| !owner_group_gids.contains(&gid)))
                })
        })
    }

    pub(super) fn inject_firewall_expression_owner_uid_scope(
        rule: &mut FirewallRule,
        owner_uid: u32,
    ) {
        rule.expressions.push(FirewallExpression {
            statement: Some(FirewallStatement {
                op: "==".to_string(),
                name: "meta".to_string(),
                values: vec![FirewallStatementValue {
                    key: "skuid".to_string(),
                    value: owner_uid.to_string(),
                }],
            }),
        });
    }

    pub(super) fn firewall_matches_owner_scope(firewall: &FirewallConfig, owner_uid: u32) -> bool {
        // nftables chains require elevated access; only iptables-style flat rules
        // can be owner-scoped transparently.
        if !firewall.chains.is_empty() {
            return false;
        }
        if firewall.rules.is_empty() {
            return false;
        }

        let owner_group_gids = Self::group_memberships_for_uid(owner_uid);

        firewall.rules.iter().all(|rule| {
            Self::firewall_rule_matches_owner_scope(rule, owner_uid, owner_group_gids.as_slice())
        })
    }

    pub(super) fn operator_owner_scope_conflicts(
        operator: &RuleOperator,
        owner_uid: u32,
        owner_username: Option<&str>,
        owner_group_gids: &[u32],
        saw_owner_match: &mut bool,
    ) -> bool {
        if operator.operand.eq_ignore_ascii_case("user.id") {
            let Ok(candidate_uid) = operator.data.trim().parse::<u32>() else {
                return true;
            };
            if candidate_uid != owner_uid {
                return true;
            }
            *saw_owner_match = true;
        }

        if operator.operand.eq_ignore_ascii_case("user.name") {
            let Some(owner_username) = owner_username else {
                return true;
            };
            if operator.data.trim() != owner_username {
                return true;
            }
            *saw_owner_match = true;
        }

        if operator.operand.eq_ignore_ascii_case("user.gid") {
            let Ok(candidate_gid) = operator.data.trim().parse::<u32>() else {
                return true;
            };
            if !owner_group_gids.contains(&candidate_gid) {
                return true;
            }
            *saw_owner_match = true;
        }

        operator.list.iter().any(|nested| {
            Self::operator_owner_scope_conflicts(
                nested,
                owner_uid,
                owner_username,
                owner_group_gids,
                saw_owner_match,
            )
        })
    }

    pub(super) fn firewall_parameters_have_conflicting_owner_scope(
        parameters: &str,
        owner_uid: u32,
        owner_group_gids: &[u32],
    ) -> bool {
        let uid_text = owner_uid.to_string();
        let tokens: Vec<&str> = parameters.split_ascii_whitespace().collect();
        for index in 0..tokens.len() {
            if tokens[index] == "--uid-owner"
                && let Some(candidate) = tokens.get(index + 1)
            {
                return *candidate != uid_text.as_str();
            }
            if tokens[index] == "--gid-owner"
                && let Some(candidate_gid) =
                    tokens.get(index + 1).and_then(|g| g.parse::<u32>().ok())
            {
                return !owner_group_gids.contains(&candidate_gid);
            }
            if tokens[index].eq_ignore_ascii_case("skuid") {
                if let Some(candidate) = tokens.get(index + 1)
                    && *candidate != uid_text.as_str()
                    && *candidate != "="
                    && *candidate != "=="
                {
                    return true;
                }
                if matches!(tokens.get(index + 1), Some(&"=") | Some(&"=="))
                    && let Some(candidate) = tokens.get(index + 2)
                {
                    return *candidate != uid_text.as_str();
                }
            }
            if tokens[index].eq_ignore_ascii_case("skgid") {
                if let Some(candidate) = tokens.get(index + 1)
                    && *candidate != "="
                    && *candidate != "=="
                    && let Ok(candidate_gid) = candidate.parse::<u32>()
                {
                    return !owner_group_gids.contains(&candidate_gid);
                }
                if matches!(tokens.get(index + 1), Some(&"=") | Some(&"=="))
                    && let Some(candidate_gid) =
                        tokens.get(index + 2).and_then(|g| g.parse::<u32>().ok())
                {
                    return !owner_group_gids.contains(&candidate_gid);
                }
            }
        }
        false
    }

    pub(super) fn inject_owner_uid_scope(rule: &mut RuleRecord, owner_uid: u32) {
        // Only inject when the rule already carries a meaningful operator.
        if rule.operator.is_empty() {
            return;
        }
        let existing_operator = std::mem::take(&mut rule.operator);
        let owner_operator = RuleOperator {
            type_name: "simple".to_string(),
            operand: "user.id".to_string(),
            data: owner_uid.to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        };
        rule.operator = RuleOperator {
            type_name: "list".to_string(),
            operand: String::new(),
            data: String::new(),
            sensitive: false,
            scope: None,
            list: vec![existing_operator, owner_operator],
        };
    }
}

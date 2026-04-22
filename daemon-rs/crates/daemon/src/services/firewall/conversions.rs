use opensnitch_proto::pb;

use crate::models::firewall_state::FirewallBackend;
use crate::models::firewall_storage::{
    PersistedExpressions, PersistedFwChain, PersistedFwChains, PersistedFwRule, PersistedStatement,
    PersistedStatementValue, RawExpressions, RawFwChain, RawFwChains, RawFwRule, RawStatement,
    RawStatementValue,
};
use crate::utils::name_parsing::normalized_name;

pub(crate) fn parse_firewall_backend(name: &str) -> FirewallBackend {
    match normalized_name(name).as_str() {
        "iptables" => FirewallBackend::Iptables,
        _ => FirewallBackend::Nftables,
    }
}

pub(crate) fn firewall_backend_name(backend: FirewallBackend) -> &'static str {
    match backend {
        FirewallBackend::Nftables => "nftables",
        FirewallBackend::Iptables => "iptables",
    }
}

impl From<RawFwChains> for pb::FwChains {
    fn from(value: RawFwChains) -> Self {
        Self {
            rule: value.rule.map(pb::FwRule::from),
            chains: value.chains.into_iter().map(pb::FwChain::from).collect(),
        }
    }
}

impl From<RawFwChain> for pb::FwChain {
    fn from(value: RawFwChain) -> Self {
        Self {
            name: value.name,
            table: value.table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules: value.rules.into_iter().map(pb::FwRule::from).collect(),
        }
    }
}

impl From<RawFwRule> for pb::FwRule {
    fn from(value: RawFwRule) -> Self {
        Self {
            table: value.table,
            chain: value.chain,
            uuid: value.uuid,
            enabled: value.enabled,
            position: value.position,
            description: value.description,
            parameters: value.parameters,
            expressions: value
                .expressions
                .into_iter()
                .map(pb::Expressions::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<RawExpressions> for pb::Expressions {
    fn from(value: RawExpressions) -> Self {
        Self {
            statement: value.statement.map(pb::Statement::from),
        }
    }
}

impl From<RawStatement> for pb::Statement {
    fn from(value: RawStatement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(pb::StatementValues::from)
                .collect(),
        }
    }
}

impl From<RawStatementValue> for pb::StatementValues {
    fn from(value: RawStatementValue) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

impl From<pb::FwChains> for PersistedFwChains {
    fn from(value: pb::FwChains) -> Self {
        Self {
            rule: value.rule.map(PersistedFwRule::from),
            chains: value
                .chains
                .into_iter()
                .map(PersistedFwChain::from)
                .collect(),
        }
    }
}

impl From<pb::FwChain> for PersistedFwChain {
    fn from(value: pb::FwChain) -> Self {
        Self {
            name: value.name,
            table: value.table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules: value.rules.into_iter().map(PersistedFwRule::from).collect(),
        }
    }
}

impl From<pb::FwRule> for PersistedFwRule {
    fn from(value: pb::FwRule) -> Self {
        Self {
            table: value.table,
            chain: value.chain,
            uuid: value.uuid,
            enabled: value.enabled,
            position: value.position,
            description: value.description,
            parameters: value.parameters,
            expressions: value
                .expressions
                .into_iter()
                .map(PersistedExpressions::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<pb::Expressions> for PersistedExpressions {
    fn from(value: pb::Expressions) -> Self {
        Self {
            statement: value.statement.map(PersistedStatement::from),
        }
    }
}

impl From<pb::Statement> for PersistedStatement {
    fn from(value: pb::Statement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(PersistedStatementValue::from)
                .collect(),
        }
    }
}

impl From<pb::StatementValues> for PersistedStatementValue {
    fn from(value: pb::StatementValues) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

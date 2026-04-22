use opensnitch_proto::pb;

use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue,
};
use crate::models::firewall_state::FirewallBackend;
use crate::models::firewall_storage::{
    PersistedFirewallChain, PersistedFirewallExpression, PersistedFirewallRule,
    PersistedFirewallStatement, PersistedFirewallStatementValue, RawFirewallChain,
    RawFirewallExpression, RawFirewallRule, RawFirewallStatement, RawFirewallStatementValue,
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

// ── file ingress: Raw* → domain ───────────────────────────────────────────────

// Note: RawFirewallGroup (the `FwChains` compat wrapper) is consumed inline
// during FirewallConfig construction in storage.rs; its constituent types
// convert here via the impls below.

impl From<RawFirewallChain> for FirewallChain {
    fn from(value: RawFirewallChain) -> Self {
        // Move table/name first so they can be borrowed by the rules closure
        // without conflicting with the partial move of value.rules.
        let table = value.table;
        let name = value.name;
        let rules = value
            .rules
            .into_iter()
            .map(|raw_rule| {
                let mut rule = FirewallRule::from(raw_rule);
                // The Go daemon legacy format omits Table/Chain on nested rules;
                // inherit from parent chain so downstream code has the full context.
                if rule.table.is_empty() {
                    rule.table.clone_from(&table);
                }
                if rule.chain.is_empty() {
                    rule.chain.clone_from(&name);
                }
                rule
            })
            .collect();
        Self {
            name,
            table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules,
        }
    }
}

impl From<RawFirewallRule> for FirewallRule {
    fn from(value: RawFirewallRule) -> Self {
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
                .map(FirewallExpression::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<RawFirewallExpression> for FirewallExpression {
    fn from(value: RawFirewallExpression) -> Self {
        Self {
            statement: value.statement.map(FirewallStatement::from),
        }
    }
}

impl From<RawFirewallStatement> for FirewallStatement {
    fn from(value: RawFirewallStatement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(FirewallStatementValue::from)
                .collect(),
        }
    }
}

impl From<RawFirewallStatementValue> for FirewallStatementValue {
    fn from(value: RawFirewallStatementValue) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

// ── gRPC ingress: pb::* → domain ──────────────────────────────────────────────
//
// `pb::SysFirewall.system_rules` is a `Vec<pb::FwChains>` — a deprecated compat
// wrapper that mixed a flat iptables rule with nftables chains.  We flatten it
// here at the adapter boundary so the domain never sees the wrapper.

impl From<pb::SysFirewall> for FirewallConfig {
    fn from(value: pb::SysFirewall) -> Self {
        let mut rules = Vec::new();
        let mut chains = Vec::new();
        for group in value.system_rules {
            if let Some(rule) = group.rule {
                rules.push(FirewallRule::from(rule));
            }
            chains.extend(group.chains.into_iter().map(FirewallChain::from));
        }
        Self {
            enabled: value.enabled,
            version: value.version,
            rules,
            chains,
        }
    }
}

impl From<pb::FwChain> for FirewallChain {
    fn from(value: pb::FwChain) -> Self {
        let table = value.table;
        let name = value.name;
        let rules = value
            .rules
            .into_iter()
            .map(|pb_rule| {
                let mut rule = FirewallRule::from(pb_rule);
                if rule.table.is_empty() {
                    rule.table.clone_from(&table);
                }
                if rule.chain.is_empty() {
                    rule.chain.clone_from(&name);
                }
                rule
            })
            .collect();
        Self {
            name,
            table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules,
        }
    }
}

impl From<pb::FwRule> for FirewallRule {
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
                .map(FirewallExpression::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<pb::Expressions> for FirewallExpression {
    fn from(value: pb::Expressions) -> Self {
        Self {
            statement: value.statement.map(FirewallStatement::from),
        }
    }
}

impl From<pb::Statement> for FirewallStatement {
    fn from(value: pb::Statement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(FirewallStatementValue::from)
                .collect(),
        }
    }
}

impl From<pb::StatementValues> for FirewallStatementValue {
    fn from(value: pb::StatementValues) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

// ── gRPC egress: domain → pb::* ───────────────────────────────────────────────
//
// Used only at the gRPC subscribe handshake boundary in `services/client` and
// inside the `platform/ports` firewall port implementations.
//
// We reconstruct the deprecated `pb::FwChains` wrapper here so the wire format
// stays backward-compatible: each iptables rule becomes a singleton FwChains
// entry; each nftables chain becomes its own singleton FwChains entry.

impl From<&FirewallConfig> for pb::SysFirewall {
    fn from(value: &FirewallConfig) -> Self {
        let mut system_rules: Vec<pb::FwChains> = value
            .rules
            .iter()
            .map(|rule| pb::FwChains {
                rule: Some(pb::FwRule::from(rule)),
                chains: Vec::new(),
            })
            .collect();
        for chain in &value.chains {
            system_rules.push(pb::FwChains {
                rule: None,
                chains: vec![pb::FwChain::from(chain)],
            });
        }
        Self {
            enabled: value.enabled,
            version: value.version,
            system_rules,
        }
    }
}

impl From<&FirewallChain> for pb::FwChain {
    fn from(value: &FirewallChain) -> Self {
        Self {
            name: value.name.clone(),
            table: value.table.clone(),
            family: value.family.clone(),
            priority: value.priority.clone(),
            r#type: value.r#type.clone(),
            hook: value.hook.clone(),
            policy: value.policy.clone(),
            rules: value.rules.iter().map(pb::FwRule::from).collect(),
        }
    }
}

impl From<&FirewallRule> for pb::FwRule {
    fn from(value: &FirewallRule) -> Self {
        Self {
            table: value.table.clone(),
            chain: value.chain.clone(),
            uuid: value.uuid.clone(),
            enabled: value.enabled,
            position: value.position,
            description: value.description.clone(),
            parameters: value.parameters.clone(),
            expressions: value
                .expressions
                .iter()
                .map(pb::Expressions::from)
                .collect(),
            target: value.target.clone(),
            target_parameters: value.target_parameters.clone(),
        }
    }
}

impl From<&FirewallExpression> for pb::Expressions {
    fn from(value: &FirewallExpression) -> Self {
        Self {
            statement: value.statement.as_ref().map(pb::Statement::from),
        }
    }
}

impl From<&FirewallStatement> for pb::Statement {
    fn from(value: &FirewallStatement) -> Self {
        Self {
            op: value.op.clone(),
            name: value.name.clone(),
            values: value.values.iter().map(pb::StatementValues::from).collect(),
        }
    }
}

impl From<&FirewallStatementValue> for pb::StatementValues {
    fn from(value: &FirewallStatementValue) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

// ── file egress: domain → Persisted* ─────────────────────────────────────────
//
// The PersistedFirewallGroup (SystemRules entry) wrapper is reconstructed in
// storage.rs to preserve backward-compatible JSON file format.

impl From<FirewallChain> for PersistedFirewallChain {
    fn from(value: FirewallChain) -> Self {
        Self {
            name: value.name,
            table: value.table,
            family: value.family,
            priority: value.priority,
            r#type: value.r#type,
            hook: value.hook,
            policy: value.policy,
            rules: value
                .rules
                .into_iter()
                .map(PersistedFirewallRule::from)
                .collect(),
        }
    }
}

impl From<FirewallRule> for PersistedFirewallRule {
    fn from(value: FirewallRule) -> Self {
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
                .map(PersistedFirewallExpression::from)
                .collect(),
            target: value.target,
            target_parameters: value.target_parameters,
        }
    }
}

impl From<FirewallExpression> for PersistedFirewallExpression {
    fn from(value: FirewallExpression) -> Self {
        Self {
            statement: value.statement.map(PersistedFirewallStatement::from),
        }
    }
}

impl From<FirewallStatement> for PersistedFirewallStatement {
    fn from(value: FirewallStatement) -> Self {
        Self {
            op: value.op,
            name: value.name,
            values: value
                .values
                .into_iter()
                .map(PersistedFirewallStatementValue::from)
                .collect(),
        }
    }
}

impl From<FirewallStatementValue> for PersistedFirewallStatementValue {
    fn from(value: FirewallStatementValue) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

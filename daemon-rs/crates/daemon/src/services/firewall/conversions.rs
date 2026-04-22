use transport_wire_core;

use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue, FirewallZone,
};
use crate::models::firewall_state::FirewallBackend;
use crate::models::firewall_storage::{
    PersistedFirewallChain, PersistedFirewallExpression, PersistedFirewallRule,
    PersistedFirewallStatement, PersistedFirewallStatementValue, PersistedFirewallZone,
    RawFirewallChain, RawFirewallExpression, RawFirewallRule, RawFirewallStatement,
    RawFirewallStatementValue, RawFirewallZone,
};
use crate::utils::name_parsing::normalized_name;

pub(crate) fn parse_firewall_backend(name: &str) -> FirewallBackend {
    match normalized_name(name).as_str() {
        #[cfg(feature = "openwrt")]
        "openwrt" | "openwrtuci" | "openwrt-uci" | "firewall4" | "uci" => {
            FirewallBackend::OpenWrtUci
        }
        "iptables" => FirewallBackend::Iptables,
        _ => FirewallBackend::Nftables,
    }
}

pub(crate) fn firewall_backend_name(backend: FirewallBackend) -> &'static str {
    match backend {
        FirewallBackend::Nftables => "nftables",
        FirewallBackend::Iptables => "iptables",
        FirewallBackend::OpenWrtUci => "openwrt-uci",
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

impl From<RawFirewallZone> for FirewallZone {
    fn from(value: RawFirewallZone) -> Self {
        Self {
            name: value.name,
            chains: value.chains.into_iter().map(FirewallChain::from).collect(),
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

impl From<&FirewallConfig> for transport_wire_core::WireSysFirewall {
    fn from(value: &FirewallConfig) -> Self {
        Self {
            enabled: value.enabled,
            version: value.version,
            rules: value
                .rules
                .iter()
                .map(transport_wire_core::WireFwRule::from)
                .collect(),
            chains: value
                .chains
                .iter()
                .map(transport_wire_core::WireFwChain::from)
                .collect(),
        }
    }
}

impl From<&FirewallChain> for transport_wire_core::WireFwChain {
    fn from(value: &FirewallChain) -> Self {
        Self {
            name: value.name.clone(),
            table: value.table.clone(),
            family: value.family.clone(),
            priority: value.priority.clone(),
            type_name: value.r#type.clone(),
            hook: value.hook.clone(),
            policy: value.policy.clone(),
            rules: value
                .rules
                .iter()
                .map(transport_wire_core::WireFwRule::from)
                .collect(),
        }
    }
}

impl From<&FirewallRule> for transport_wire_core::WireFwRule {
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
                .map(transport_wire_core::WireFwExpression::from)
                .collect(),
            target: value.target.clone(),
            target_parameters: value.target_parameters.clone(),
        }
    }
}

impl From<&FirewallExpression> for transport_wire_core::WireFwExpression {
    fn from(value: &FirewallExpression) -> Self {
        Self {
            statement: value
                .statement
                .as_ref()
                .map(transport_wire_core::WireFwStatement::from),
        }
    }
}

impl From<&FirewallStatement> for transport_wire_core::WireFwStatement {
    fn from(value: &FirewallStatement) -> Self {
        Self {
            op: value.op.clone(),
            name: value.name.clone(),
            values: value
                .values
                .iter()
                .map(transport_wire_core::WireFwStatementValue::from)
                .collect(),
        }
    }
}

impl From<&FirewallStatementValue> for transport_wire_core::WireFwStatementValue {
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

impl From<FirewallZone> for PersistedFirewallZone {
    fn from(value: FirewallZone) -> Self {
        Self {
            name: value.name,
            chains: value
                .chains
                .into_iter()
                .map(PersistedFirewallChain::from)
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

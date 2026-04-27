/// Canonical domain representation of the system firewall configuration.
///
/// These types capture the intent of the firewall domain model without any
/// coupling to transport formats (protobuf) or file formats (JSON/serde).
///
/// The deprecated `pb::FwChains` transport wrapper (which mixed a flat iptables
/// rule with a list of nftables chains for backward compat) is **not** modelled
/// here.  Instead, rules and chains are held in separate flat collections:
/// - `rules`  — legacy iptables flat rules (from the deprecated `FwChains.Rule` field).
/// - `chains` — nftables named chains       (from `FwChains.Chains`).
///
/// Zone support is modeled as a separate top-level `zones` field so adapter
/// boundaries can map zone-native backends (firewalld/OpenWrt/VyOS) without
/// overloading flat chain/rule paths.
///
/// Conversion directions are implemented in `services/firewall/conversions`:
/// - File ingress:  `RawFirewallConfig → FirewallConfig`   (JSON file → domain; flattens deprecated group wrapper)
/// - Wire ingress:  `pb::SysFirewall → FirewallConfig`     (gRPC stream → domain; flattens deprecated group wrapper)
/// - Wire egress:   `&FirewallConfig → pb::SysFirewall`    (domain → gRPC; reconstructs deprecated group wrapper)
/// - File egress:   `FirewallConfig → PersistedFirewallConfig`  (domain → JSON; reconstructs deprecated group wrapper)
#[derive(Debug, Clone, Default)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub version: u32,
    /// Flat iptables rules.  Sourced from the deprecated `FwChains.Rule` proto field.
    pub rules: Vec<FirewallRule>,
    /// Named nftables chains.  Sourced from `FwChains.Chains`.
    pub chains: Vec<FirewallChain>,
    /// Zone-oriented firewall groups (nftables/firewalld/OpenWrt adapter boundary).
    pub zones: Vec<FirewallZone>,
}

/// A named firewall zone owning one or more chains.
#[derive(Debug, Clone, Default)]
pub struct FirewallZone {
    pub name: String,
    pub chains: Vec<FirewallChain>,
}

/// A named firewall chain with its own set of rules (nftables / iptables).
#[derive(Debug, Clone, Default)]
pub struct FirewallChain {
    pub name: String,
    pub table: String,
    pub family: String,
    pub priority: String,
    pub r#type: String,
    pub hook: String,
    pub policy: String,
    pub rules: Vec<FirewallRule>,
}

/// A single firewall rule entry.
#[derive(Debug, Clone, Default)]
pub struct FirewallRule {
    pub table: String,
    pub chain: String,
    pub uuid: String,
    pub enabled: bool,
    pub position: u64,
    pub description: String,
    pub parameters: String,
    pub expressions: Vec<FirewallExpression>,
    pub target: String,
    pub target_parameters: String,
}

/// A single match expression (nftables expression / iptables match).
#[derive(Debug, Clone, Default)]
pub struct FirewallExpression {
    pub statement: Option<FirewallStatement>,
}

/// The match statement carried by a `FirewallExpression`.
#[derive(Debug, Clone, Default)]
pub struct FirewallStatement {
    pub op: String,
    pub name: String,
    pub values: Vec<FirewallStatementValue>,
}

/// A key/value pair within a `FirewallStatement`.
#[derive(Debug, Clone, Default)]
pub struct FirewallStatementValue {
    pub key: String,
    pub value: String,
}

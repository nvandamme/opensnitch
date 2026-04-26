use anyhow::{Context, Result};
use netlink_bindings::nftables::{self, Nfgenmsg};
use nix::libc;
use std::collections::BTreeMap;
use std::ffi::CStr;

use super::{
    FirewallNetlinkAdapter, FirewallNetlinkOperation, GenerationId, INTERCEPTION_DNS_TAG,
    INTERCEPTION_NON_TCP_TAG, INTERCEPTION_TCP_SYN_TAG, NetfilterTransactionBuilder,
    NetlinkExecutionSummary, NetlinkFallbackReason, NetlinkFallbackRequired, NftChain, NftRule,
    NftTable, TransactionOutcome,
};
use crate::models::firewall_config::{FirewallChain, FirewallConfig, FirewallRule};
use crate::platform::firewall::nftables::FirewallNftablesAdapter;
use crate::platform::netlink::io::{
    ReplyVisit, for_each_reply, for_each_reply_until,
};
use crate::utils::conntrack::flush_conntrack_table;

use netlink_socket2::NetlinkSocket;

impl FirewallNetlinkOperation {
    fn kind(&self) -> &'static str {
        match self {
            FirewallNetlinkOperation::EnsureBaseChains { .. } => "ensure_base_chains",
            FirewallNetlinkOperation::DisableBaseTable { .. } => "disable_base_table",
            FirewallNetlinkOperation::ValidateInterceptionRules => "validate_interception_rules",
            FirewallNetlinkOperation::EnsureInterceptionRule { .. } => "ensure_interception_rule",
            FirewallNetlinkOperation::EnsureSystemChain { .. } => "ensure_system_chain",
            FirewallNetlinkOperation::ApplySystemRule { .. } => "apply_system_rule",
            FirewallNetlinkOperation::ClearTaggedSystemRules { .. } => "clear_tagged_system_rules",
        }
    }
}

fn unsupported_expression_for_operation(op: &FirewallNetlinkOperation) -> Option<&str> {
    match op {
        FirewallNetlinkOperation::EnsureInterceptionRule { expression, .. } => Some(expression),
        _ => None,
    }
}

fn unsupported_expression_family_from_parse_failure(
    expression: &str,
    parse_failure: Option<super::ParseError>,
) -> &'static str {
    let classified = NftRule::classify_expression_family(expression);
    match parse_failure {
        Some(parse_failure) => {
            if classified == "set_or_list"
                && matches!(
                    parse_failure.class,
                    super::ParseFailureClass::InvalidValue
                        | super::ParseFailureClass::AmbiguousForm
                )
            {
                return classified;
            }

            let parsed_family = parse_failure.family.as_str();
            if parsed_family != "other" {
                return parsed_family;
            }

            match parse_failure.class {
                super::ParseFailureClass::EmptyExpression => {}
                super::ParseFailureClass::UnsupportedShape
                | super::ParseFailureClass::InvalidValue
                | super::ParseFailureClass::AmbiguousForm
                | super::ParseFailureClass::TrailingTokens => {}
            }
        }
        None => {}
    }

    if classified != "other" {
        return classified;
    }

    "other"
}

fn unsupported_summary_for_ops(
    ops: &[FirewallNetlinkOperation],
) -> (Vec<&'static str>, Vec<(&'static str, usize)>) {
    let mut unsupported_ops = Vec::new();
    let mut unsupported_expression_families: BTreeMap<&'static str, usize> = BTreeMap::new();
    for op in ops {
        unsupported_ops.push(op.kind());
        if let Some(expression) = unsupported_expression_for_operation(op) {
            let parse_failure = NftRule::parse_failure(expression);
            let family =
                unsupported_expression_family_from_parse_failure(expression, parse_failure);
            *unsupported_expression_families.entry(family).or_insert(0) += 1;
        }
    }
    (
        unsupported_ops,
        unsupported_expression_families.into_iter().collect(),
    )
}

#[derive(Debug, Clone)]
struct DumpChain {
    family: &'static str,
    table: String,
    name: String,
    hook: &'static str,
    priority: String,
    policy: &'static str,
    chain_type: String,
}

#[derive(Debug, Clone)]
struct DumpRule {
    family: &'static str,
    table: String,
    chain: String,
    position: u64,
    uuid: String,
    parameters: String,
}

const NFT_DUMP_FAMILIES: [&str; 5] = ["inet", "ip", "ip6", "bridge", "netdev"];

// Netlink string helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn cstr_to_string(value: &CStr) -> String {
    value.to_string_lossy().into_owned()
}

// Netlink hook-name helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn hook_num_to_name(num: u32) -> &'static str {
    match num {
        n if n == libc::NF_INET_PRE_ROUTING as u32 => "prerouting",
        n if n == libc::NF_INET_LOCAL_IN as u32 => "input",
        n if n == libc::NF_INET_FORWARD as u32 => "forward",
        n if n == libc::NF_INET_LOCAL_OUT as u32 => "output",
        n if n == libc::NF_INET_POST_ROUTING as u32 => "postrouting",
        n if n == libc::NF_INET_INGRESS as u32 => "ingress",
        _ => "",
    }
}

// Netlink policy-name helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn policy_num_to_name(policy: u32) -> &'static str {
    match policy {
        n if n == nftables::VerdictCode::Accept as u32 => "accept",
        n if n == nftables::VerdictCode::Drop as u32 => "drop",
        _ => "",
    }
}

// Zone-name helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn zone_name_from_chain(chain_name: &str) -> Option<&str> {
    let name = chain_name.trim();
    let rest = name.strip_prefix("zone_")?;
    let last_sep = rest.rfind('_')?;
    let zone = rest[..last_sep].trim();
    if zone.is_empty() {
        return None;
    }
    Some(zone)
}

// Sysfw tag parser retained for optional dump/introspection paths.
#[allow(dead_code)]
fn tagged_uuid_from_userdata(userdata: &[u8]) -> String {
    if !userdata.starts_with(super::SYSFW_TAG_PREFIX) {
        return String::new();
    }
    String::from_utf8_lossy(&userdata[super::SYSFW_TAG_PREFIX.len()..]).into_owned()
}

impl FirewallNetlinkAdapter {
    fn parse_system_rule(rule: &FirewallRule, queue_num: u16) -> Option<Vec<NftRule>> {
        if !rule.expressions.is_empty() {
            return NftRule::parse_structured_rule(rule, queue_num);
        }

        let expression = FirewallNftablesAdapter::probe_nft_expression(rule, queue_num);
        if expression.is_empty() {
            return None;
        }
        NftRule::parse_all(&expression)
    }

    pub fn preflight() -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket for recovery")
    }

    pub async fn ensure(queue_num: u16, queue_bypass: bool) -> Result<()> {
        let plan = Self::plan_ensure(queue_num, queue_bypass);
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .map_err(|err| {
                NetlinkFallbackRequired::new(
                    NetlinkFallbackReason::TransactionExecutionFailed,
                    format!("ensure transaction failed: {err}"),
                )
            })?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            Self::flush_conntrack().await;
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables ensure partially handled via netlink; falling back for remaining ops"
        );
        Err(NetlinkFallbackRequired::new(
            NetlinkFallbackReason::PartialUnsupportedOps,
            "nftables ensure partially handled via netlink",
        )
        .into())
    }

    pub async fn disable() -> Result<()> {
        let plan = vec![FirewallNetlinkOperation::DisableBaseTable {
            table: NftTable::opensnitch(),
        }];
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .map_err(|err| {
                NetlinkFallbackRequired::new(
                    NetlinkFallbackReason::TransactionExecutionFailed,
                    format!("disable transaction failed: {err}"),
                )
            })?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables disable partially handled via netlink; falling back for remaining ops"
        );
        Err(NetlinkFallbackRequired::new(
            NetlinkFallbackReason::PartialUnsupportedOps,
            "nftables disable partially handled via netlink",
        )
        .into())
    }

    pub async fn interception_rules_valid() -> Result<bool> {
        let plan = vec![FirewallNetlinkOperation::ValidateInterceptionRules];
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .map_err(|err| {
                NetlinkFallbackRequired::new(
                    NetlinkFallbackReason::TransactionExecutionFailed,
                    format!("interception validation transaction failed: {err}"),
                )
            })?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return FirewallNftablesAdapter::interception_rules_valid()
                .await
                .context("validate interception rules after netlink execution");
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables validation requires compatibility path"
        );
        Err(NetlinkFallbackRequired::new(
            NetlinkFallbackReason::CompatibilityValidationRequired,
            "nftables interception validation requires compatibility fallback",
        )
        .into())
    }

    pub async fn apply_system_firewall(sysfw: &FirewallConfig, queue_num: u16) -> Result<()> {
        let dropped_unsupported_rules = Self::count_dropped_system_fw_rules(sysfw, queue_num);
        let plan = Self::plan_apply_system_firewall(sysfw, queue_num);
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .map_err(|err| {
                NetlinkFallbackRequired::new(
                    NetlinkFallbackReason::TransactionExecutionFailed,
                    format!("system firewall apply transaction failed: {err}"),
                )
            })?;

        if matches!(summary.outcome, TransactionOutcome::Full) && dropped_unsupported_rules == 0 {
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            dropped_unsupported_rules,
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables apply partially handled via netlink; falling back for remaining ops"
        );
        let reason = if dropped_unsupported_rules > 0 {
            NetlinkFallbackReason::DroppedUnsupportedRules
        } else {
            NetlinkFallbackReason::PartialUnsupportedOps
        };
        Err(
            NetlinkFallbackRequired::new(reason, "nftables apply partially handled via netlink")
                .into(),
        )
    }

    pub async fn clear_system_firewall(sysfw: &FirewallConfig) -> Result<()> {
        let plan = Self::plan_clear_system_firewall(sysfw);
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .map_err(|err| {
                NetlinkFallbackRequired::new(
                    NetlinkFallbackReason::TransactionExecutionFailed,
                    format!("system firewall clear transaction failed: {err}"),
                )
            })?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables clear requires compatibility path"
        );
        Err(NetlinkFallbackRequired::new(
            NetlinkFallbackReason::PartialUnsupportedOps,
            "nftables clear partially handled via netlink",
        )
        .into())
    }
    pub async fn extract_system_firewall() -> Result<FirewallConfig> {
        let mut sock = crate::platform::netlink::io::new_request_socket();
        let chains = Self::dump_chains(&mut sock)
            .await
            .context("dump nftables chains over netlink")?;
        let rules = Self::dump_rules(&mut sock)
            .await
            .context("dump nftables rules over netlink")?;

        Ok(Self::compose_dumped_config(chains, rules))
    }

    fn compose_dumped_config(chains: Vec<DumpChain>, rules: Vec<DumpRule>) -> FirewallConfig {
        let mut by_key =
            std::collections::BTreeMap::<(String, String, String), FirewallChain>::new();

        for chain in chains {
            let family = chain.family.to_string();
            let key = (family.clone(), chain.table.clone(), chain.name.clone());
            by_key.insert(
                key,
                FirewallChain {
                    name: chain.name,
                    table: chain.table,
                    family,
                    priority: chain.priority,
                    r#type: chain.chain_type,
                    hook: chain.hook.to_string(),
                    policy: chain.policy.to_string(),
                    rules: Vec::new(),
                },
            );
        }

        for rule in rules {
            let family = rule.family.to_string();
            let key = (family.clone(), rule.table.clone(), rule.chain.clone());
            let chain = by_key.entry(key).or_insert_with(|| FirewallChain {
                name: rule.chain.clone(),
                table: rule.table.clone(),
                family,
                ..Default::default()
            });

            chain
                .rules
                .push(crate::models::firewall_config::FirewallRule {
                    table: rule.table,
                    chain: rule.chain,
                    uuid: rule.uuid,
                    enabled: true,
                    position: rule.position,
                    description: String::new(),
                    parameters: rule.parameters,
                    expressions: Vec::new(),
                    target: String::new(),
                    target_parameters: String::new(),
                });
        }

        for chain in by_key.values_mut() {
            chain.rules.sort_by_key(|r| r.position);
            for (idx, rule) in chain.rules.iter_mut().enumerate() {
                if rule.position == 0 {
                    rule.position = (idx as u64) + 1;
                }
            }
        }

        let mut top_level_chains = Vec::new();
        let mut zones: Vec<crate::models::firewall_config::FirewallZone> = Vec::new();
        for (_, chain) in by_key {
            if let Some(zone_name) = zone_name_from_chain(&chain.name) {
                if let Some(existing) = zones.iter_mut().find(|z| z.name == zone_name) {
                    existing.chains.push(chain);
                } else {
                    zones.push(crate::models::firewall_config::FirewallZone {
                        name: zone_name.to_string(),
                        chains: vec![chain],
                    });
                }
            } else {
                top_level_chains.push(chain);
            }
        }

        FirewallConfig {
            enabled: true,
            version: 0,
            rules: Vec::new(),
            chains: top_level_chains,
            zones,
        }
    }

    async fn dump_chains(sock: &mut NetlinkSocket) -> Result<Vec<DumpChain>> {
        let mut out = Vec::new();

        for family in NFT_DUMP_FAMILIES {
            let mut h = NetfilterTransactionBuilder::msg_header(family);
            h.set_res_id(10);
            let request = nftables::Request::new().op_getchain_dump(&h);
            for_each_reply(
                sock,
                &request,
                anyhow::Error::new,
                anyhow::Error::new,
                |(_, attrs)| {
                    let table = attrs
                        .get_table()
                        .map(cstr_to_string)
                        .unwrap_or_else(|_| String::new());
                    let name = attrs
                        .get_name()
                        .map(cstr_to_string)
                        .unwrap_or_else(|_| String::new());
                    if table.is_empty() || name.is_empty() {
                        return Ok(());
                    }

                    let chain_type = attrs
                        .get_type()
                        .map(cstr_to_string)
                        .unwrap_or_else(|_| "filter".to_string());

                    let (hook, priority) = match attrs.get_hook() {
                        Ok(hook_attrs) => {
                            let hook = hook_attrs
                                .get_num()
                                .map(hook_num_to_name)
                                .unwrap_or("");
                            let priority = hook_attrs
                                .get_priority()
                                .map(|v| v.to_string())
                                .unwrap_or_else(|_| "0".to_string());
                            (hook, priority)
                        }
                        Err(_) => ("", String::new()),
                    };

                    let policy = attrs
                        .get_policy()
                        .map(policy_num_to_name)
                        .unwrap_or("");

                    out.push(DumpChain {
                        family,
                        table,
                        name,
                        hook,
                        priority,
                        policy,
                        chain_type,
                    });
                    Ok(())
                },
            )
            .await?;
        }

        Ok(out)
    }

    async fn dump_rules(sock: &mut NetlinkSocket) -> Result<Vec<DumpRule>> {
        let mut out = Vec::new();

        for family in NFT_DUMP_FAMILIES {
            let mut h = NetfilterTransactionBuilder::msg_header(family);
            h.set_res_id(10);
            let request = nftables::Request::new().op_getrule_dump(&h);
            for_each_reply(
                sock,
                &request,
                anyhow::Error::new,
                anyhow::Error::new,
                |(_, attrs)| {
                    let table = attrs
                        .get_table()
                        .map(cstr_to_string)
                        .unwrap_or_else(|_| String::new());
                    let chain = attrs
                        .get_chain()
                        .map(cstr_to_string)
                        .unwrap_or_else(|_| String::new());
                    if table.is_empty() || chain.is_empty() {
                        return Ok(());
                    }

                    let position = attrs.get_position().unwrap_or(0);
                    let uuid = attrs
                        .get_userdata()
                        .map(tagged_uuid_from_userdata)
                        .unwrap_or_else(|_| String::new());
                    let parameters = attrs
                        .get_expressions()
                        .map(|exprs| format!("{exprs:?}"))
                        .unwrap_or_else(|_| String::new());

                    out.push(DumpRule {
                        family,
                        table,
                        chain,
                        position,
                        uuid,
                        parameters,
                    });
                    Ok(())
                },
            )
            .await?;
        }

        Ok(out)
    }
    #[cfg(test)]
    pub(crate) fn probe_compose_dumped_config() -> FirewallConfig {
        Self::compose_dumped_config(
            vec![
                DumpChain {
                    family: "inet",
                    table: "opensnitch".to_string(),
                    name: "filter_input".to_string(),
                    hook: "input",
                    priority: "0".to_string(),
                    policy: "accept",
                    chain_type: "filter".to_string(),
                },
                DumpChain {
                    family: "inet",
                    table: "opensnitch".to_string(),
                    name: "zone_wan_input".to_string(),
                    hook: "input",
                    priority: "0".to_string(),
                    policy: "drop",
                    chain_type: "filter".to_string(),
                },
            ],
            vec![
                DumpRule {
                    family: "inet",
                    table: "opensnitch".to_string(),
                    chain: "filter_input".to_string(),
                    position: 1,
                    uuid: "ssh".to_string(),
                    parameters: "meta l4proto tcp".to_string(),
                },
                DumpRule {
                    family: "inet",
                    table: "opensnitch".to_string(),
                    chain: "zone_wan_input".to_string(),
                    position: 2,
                    uuid: String::new(),
                    parameters: "ip saddr 198.51.100.0/24".to_string(),
                },
            ],
        )
    }

    async fn execute_plan_with_netlink(
        ops: &[FirewallNetlinkOperation],
    ) -> Result<NetlinkExecutionSummary> {
        if ops.is_empty() {
            return Ok(NetlinkExecutionSummary {
                outcome: TransactionOutcome::Full,
                unsupported_ops: Vec::new(),
                unsupported_expression_families: Vec::new(),
            });
        }

        let mut socket = crate::platform::netlink::io::new_request_socket();
        let genid = GenerationId::new_latest(&mut socket)
            .await
            .context("query current nftables generation id")?;
        let mut tx = NetfilterTransactionBuilder::new(&mut socket, genid);

        let mut all_supported = true;
        let mut unsupported_netlink_ops = Vec::new();
        for op in ops {
            if !tx
                .apply_operation(&mut socket, op)
                .await
                .context("apply netlink operation")?
            {
                all_supported = false;
                unsupported_netlink_ops.push(op.clone());
            }
        }

        let (unsupported_ops, unsupported_expression_families) =
            unsupported_summary_for_ops(&unsupported_netlink_ops);

        if !unsupported_ops.is_empty() {
            tracing::debug!(
                total_ops = ops.len(),
                unsupported_count = unsupported_ops.len(),
                unsupported_ops = ?unsupported_ops,
                unsupported_expression_families = ?unsupported_expression_families,
                "nftables netlink left unsupported operations for CLI fallback"
            );
        }

        if tx.is_empty() {
            return Ok(NetlinkExecutionSummary {
                outcome: TransactionOutcome::Partial,
                unsupported_ops,
                unsupported_expression_families,
            });
        }

        tx.commit(&mut socket)
            .await
            .context("commit nftables netlink transaction")?;

        Ok(NetlinkExecutionSummary {
            outcome: if all_supported {
                TransactionOutcome::Full
            } else {
                TransactionOutcome::Partial
            },
            unsupported_ops,
            unsupported_expression_families,
        })
    }

    fn plan_ensure(queue_num: u16, queue_bypass: bool) -> Vec<FirewallNetlinkOperation> {
        let mut operations = vec![FirewallNetlinkOperation::EnsureBaseChains {
            queue_num,
            queue_bypass,
        }];

        let bypass = if queue_bypass { " bypass" } else { "" };
        operations.push(FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NftChain::interception_filter_input(),
            expression: format!(
                "udp sport 53 queue num {queue_num}{bypass} comment \"opensnitch-queue-dns\""
            ),
            tag: INTERCEPTION_DNS_TAG.to_string(),
        });
        operations.push(FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NftChain::interception_mangle_output(),
            expression: format!(
                "meta l4proto != tcp ct state new,related queue num {queue_num}{bypass} comment \"opensnitch-queue-connections-non-tcp\""
            ),
            tag: INTERCEPTION_NON_TCP_TAG.to_string(),
        });
        operations.push(FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NftChain::interception_mangle_output(),
            expression: format!(
                "tcp flags & (fin|syn|rst|ack) == syn queue num {queue_num}{bypass} comment \"opensnitch-queue-connections-tcp-syn\""
            ),
            tag: INTERCEPTION_TCP_SYN_TAG.to_string(),
        });

        operations
    }

    fn plan_apply_system_firewall(
        sysfw: &FirewallConfig,
        queue_num: u16,
    ) -> Vec<FirewallNetlinkOperation> {
        if !sysfw.enabled {
            return Vec::new();
        }

        let mut operations = Vec::new();

        let all_chains = sysfw
            .chains
            .iter()
            .chain(sysfw.zones.iter().flat_map(|z| z.chains.iter()));

        for chain in all_chains {
            Self::push_chain_operations(&mut operations, chain, queue_num);
        }

        operations
    }

    fn push_chain_operations(
        operations: &mut Vec<FirewallNetlinkOperation>,
        chain: &FirewallChain,
        queue_num: u16,
    ) {
        let family = FirewallNftablesAdapter::probe_family_or_default(chain);
        let table = FirewallNftablesAdapter::probe_table_or_default(chain);
        let name = FirewallNftablesAdapter::probe_chain_name_or_default(chain);
        let hook = if chain.hook.is_empty() {
            "output"
        } else {
            &chain.hook
        };
        let policy = if chain.policy.is_empty() {
            "accept"
        } else {
            &chain.policy
        };
        let priority = if chain.priority.is_empty() {
            "0"
        } else {
            &chain.priority
        };
        let chain_type = chain_type_name(chain);

        operations.push(FirewallNetlinkOperation::EnsureSystemChain {
            family: family.to_string(),
            table: table.to_string(),
            name: name.to_string(),
            hook: hook.to_string(),
            priority: priority.to_string(),
            policy: policy.to_string(),
            chain_type: chain_type.to_string(),
        });

        for rule in &chain.rules {
            if !rule.enabled {
                continue;
            }

            if let Some(parsed_rules) = Self::parse_system_rule(rule, queue_num) {
                for parsed in parsed_rules {
                    operations.push(FirewallNetlinkOperation::ApplySystemRule {
                        rule: parsed
                            .with_target(
                                NftTable::new(family, table),
                                name,
                            )
                            .with_tag(FirewallNftablesAdapter::probe_rule_tag(chain, rule)),
                    });
                }
            }
        }
    }

    fn count_dropped_system_fw_rules(sysfw: &FirewallConfig, queue_num: u16) -> usize {
        if !sysfw.enabled {
            return 0;
        }

        fn count_in_chains(chains: &[FirewallChain], queue_num: u16) -> usize {
            chains
                .iter()
                .flat_map(|chain| chain.rules.iter())
                .filter(|rule| rule.enabled)
                .filter(|rule| FirewallNetlinkAdapter::parse_system_rule(rule, queue_num).is_none())
                .count()
        }

        let top_level = count_in_chains(&sysfw.chains, queue_num);
        let zone_level = sysfw
            .zones
            .iter()
            .map(|zone| count_in_chains(&zone.chains, queue_num))
            .sum::<usize>();

        top_level + zone_level
    }

    fn plan_clear_system_firewall(sysfw: &FirewallConfig) -> Vec<FirewallNetlinkOperation> {
        let mut operations = Vec::new();
        for chain in &sysfw.chains {
            operations.push(FirewallNetlinkOperation::ClearTaggedSystemRules {
                family: FirewallNftablesAdapter::probe_family_or_default(chain).to_string(),
                table: FirewallNftablesAdapter::probe_table_or_default(chain).to_string(),
                chain: FirewallNftablesAdapter::probe_chain_name_or_default(chain).to_string(),
            });
        }

        for zone in &sysfw.zones {
            for chain in &zone.chains {
                operations.push(FirewallNetlinkOperation::ClearTaggedSystemRules {
                    family: FirewallNftablesAdapter::probe_family_or_default(chain).to_string(),
                    table: FirewallNftablesAdapter::probe_table_or_default(chain).to_string(),
                    chain: FirewallNftablesAdapter::probe_chain_name_or_default(chain).to_string(),
                });
            }
        }

        operations
    }

    fn probe_netfilter_netlink_socket() -> Result<()> {
        let _ = crate::platform::netlink::io::open_multicast_socket(libc::NETLINK_NETFILTER as u16)
            .context("failed to open NETLINK_NETFILTER socket")?;
        Ok(())
    }

    async fn flush_conntrack() {
        let _ = flush_conntrack_table().await;
    }
    #[cfg(test)]
    pub(crate) fn probe_plan_ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Vec<FirewallNetlinkOperation> {
        Self::plan_ensure(queue_num, queue_bypass)
    }
    #[cfg(test)]
    pub(crate) fn probe_plan_apply_system_firewall(
        sysfw: &FirewallConfig,
        queue_num: u16,
    ) -> Vec<FirewallNetlinkOperation> {
        Self::plan_apply_system_firewall(sysfw, queue_num)
    }
    #[cfg(test)]
    pub(crate) fn probe_plan_clear_system_firewall(
        sysfw: &FirewallConfig,
    ) -> Vec<FirewallNetlinkOperation> {
        Self::plan_clear_system_firewall(sysfw)
    }
    #[cfg(test)]
    pub(crate) fn probe_is_system_rule_expression_supported(expression: &str) -> bool {
        NftRule::parse_all(expression).is_some()
    }
    #[cfg(test)]
    pub(crate) fn probe_unsupported_expression_family(expression: &str) -> &'static str {
        unsupported_expression_family_from_parse_failure(
            expression,
            NftRule::parse_failure(expression),
        )
    }
    #[cfg(test)]
    pub(crate) fn probe_unsupported_summary_for_ops(
        ops: &[FirewallNetlinkOperation],
    ) -> (Vec<&'static str>, Vec<(&'static str, usize)>) {
        unsupported_summary_for_ops(ops)
    }
    #[cfg(test)]
    pub(crate) fn probe_count_dropped_system_fw_rules(
        sysfw: &FirewallConfig,
        queue_num: u16,
    ) -> usize {
        Self::count_dropped_system_fw_rules(sysfw, queue_num)
    }
}

impl GenerationId {
    async fn new_latest(sock: &mut NetlinkSocket) -> Result<Self> {
        let request = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
        let genid = for_each_reply_until(
            sock,
            &request,
            anyhow::Error::new,
            anyhow::Error::new,
            |(_, attrs)| {
                Ok(ReplyVisit::Break(attrs.get_id()?))
            },
        )
        .await?;
        let id = genid.context("missing nftables generation id reply")?;
        Ok(Self(id))
    }
}

fn chain_type_name(chain: &FirewallChain) -> &'static str {
    match chain.r#type.as_str() {
        "mangle" if chain.hook.eq_ignore_ascii_case("output") => "route",
        "mangle" => "filter",
        "natdest" | "natsource" | "nat" => "nat",
        "filter" => "filter",
        _ => "filter",
    }
}

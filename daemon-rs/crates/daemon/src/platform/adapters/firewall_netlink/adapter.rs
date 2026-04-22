use anyhow::{Context, Result};
use netlink_bindings::nftables::{self, Nfgenmsg};
use netlink_socket2::NetlinkSocket;
use nix::errno::Errno;
use nix::libc;
use std::collections::BTreeMap;
use std::ffi::CStr;

#[cfg(test)]
use super::ParsedRuleExpression;
use super::{
    FirewallNetlinkAdapter, FirewallNetlinkOperation, GenerationId, INTERCEPTION_DNS_TAG,
    INTERCEPTION_NON_TCP_TAG, INTERCEPTION_TCP_SYN_TAG, NetfilterRuleChain,
    NetfilterTransactionBuilder, NetlinkExecutionSummary, TransactionOutcome,
};
use crate::models::firewall_config::{FirewallChain, FirewallConfig};
use crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter;
use crate::utils::conntrack::flush_conntrack_table;

impl FirewallNetlinkOperation {
    fn kind(&self) -> &'static str {
        match self {
            FirewallNetlinkOperation::EnsureBaseChains { .. } => "ensure_base_chains",
            FirewallNetlinkOperation::DisableBaseTable => "disable_base_table",
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
        FirewallNetlinkOperation::ApplySystemRule { expression, .. }
        | FirewallNetlinkOperation::EnsureInterceptionRule { expression, .. } => Some(expression),
        _ => None,
    }
}

fn unsupported_expression_family(expression: &str) -> &'static str {
    let expr = expression.to_ascii_lowercase();
    if expr.contains("nfproto") {
        return "nfproto";
    }
    if expr.contains('/') {
        return "cidr";
    }
    if expr.contains("ct state") {
        return "ct_state";
    }
    if expr.contains("queue") {
        return "queue";
    }
    if expr.contains("{") || expr.contains("}") {
        return "set_or_list";
    }
    if expr.contains("meta") {
        return "meta";
    }
    if expr.contains("ip ") || expr.contains("ip6 ") {
        return "ip_addr_or_proto";
    }
    if expr.contains("tcp") || expr.contains("udp") || expr.contains("th ") {
        return "transport";
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
            let family = unsupported_expression_family(expression);
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
    family: String,
    table: String,
    name: String,
    hook: String,
    priority: String,
    policy: String,
    chain_type: String,
}

#[derive(Debug, Clone)]
struct DumpRule {
    family: String,
    table: String,
    chain: String,
    position: u64,
    uuid: String,
    parameters: String,
}

// Netlink string helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn cstr_to_string(value: &CStr) -> String {
    value.to_string_lossy().to_string()
}

// Netlink hook-name helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn hook_num_to_name(num: u32) -> String {
    match num {
        n if n == libc::NF_INET_PRE_ROUTING as u32 => "prerouting".to_string(),
        n if n == libc::NF_INET_LOCAL_IN as u32 => "input".to_string(),
        n if n == libc::NF_INET_FORWARD as u32 => "forward".to_string(),
        n if n == libc::NF_INET_LOCAL_OUT as u32 => "output".to_string(),
        n if n == libc::NF_INET_POST_ROUTING as u32 => "postrouting".to_string(),
        n if n == libc::NF_INET_INGRESS as u32 => "ingress".to_string(),
        _ => String::new(),
    }
}

// Netlink policy-name helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn policy_num_to_name(policy: u32) -> String {
    match policy {
        n if n == nftables::VerdictCode::Accept as u32 => "accept".to_string(),
        n if n == nftables::VerdictCode::Drop as u32 => "drop".to_string(),
        _ => String::new(),
    }
}

// Zone-name helper retained for optional dump/introspection paths.
#[allow(dead_code)]
fn zone_name_from_chain(chain_name: &str) -> Option<String> {
    let name = chain_name.trim();
    if !name.starts_with("zone_") {
        return None;
    }

    let rest = &name["zone_".len()..];
    let last_sep = rest.rfind('_')?;
    let zone = rest[..last_sep].trim();
    if zone.is_empty() {
        return None;
    }

    Some(zone.to_string())
}

// Sysfw tag parser retained for optional dump/introspection paths.
#[allow(dead_code)]
fn tagged_uuid_from_userdata(userdata: &[u8]) -> String {
    if !userdata.starts_with(super::SYSFW_TAG_PREFIX) {
        return String::new();
    }
    String::from_utf8_lossy(&userdata[super::SYSFW_TAG_PREFIX.len()..]).to_string()
}

impl FirewallNetlinkAdapter {
    pub fn preflight() -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket for recovery")
    }

    pub async fn ensure(queue_num: u16, queue_bypass: bool) -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before ensure")?;

        let plan = Self::plan_ensure(queue_num, queue_bypass);
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .context("execute netlink ensure transaction")?;

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
        FirewallNftablesAdapter::ensure(queue_num, queue_bypass)
            .await
            .context("execute ensure via compatibility nft executor")
    }

    pub async fn disable() -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before disable")?;

        let plan = vec![FirewallNetlinkOperation::DisableBaseTable];
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .context("execute netlink disable transaction")?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables disable partially handled via netlink; falling back for remaining ops"
        );
        FirewallNftablesAdapter::disable()
            .await
            .context("execute disable via compatibility nft executor")
    }

    pub async fn interception_rules_valid() -> Result<bool> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before interception validation")?;

        let plan = vec![FirewallNetlinkOperation::ValidateInterceptionRules];
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .context("execute netlink validation transaction")?;

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
        FirewallNftablesAdapter::interception_rules_valid()
            .await
            .context("execute interception validation via compatibility nft executor")
    }

    pub async fn apply_system_firewall(sysfw: &FirewallConfig, queue_num: u16) -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before system firewall apply")?;

        let plan = Self::plan_apply_system_firewall(sysfw, queue_num);
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .context("execute netlink apply transaction")?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables apply partially handled via netlink; falling back for remaining ops"
        );
        FirewallNftablesAdapter::apply_system_firewall(sysfw, queue_num)
            .await
            .context("execute system firewall apply via compatibility nft executor")
    }

    pub async fn clear_system_firewall(sysfw: &FirewallConfig) -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before system firewall clear")?;

        let plan = Self::plan_clear_system_firewall(sysfw);
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .context("execute netlink clear transaction")?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return Ok(());
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables clear requires compatibility path"
        );
        FirewallNftablesAdapter::clear_system_firewall(sysfw)
            .await
            .context("execute system firewall clear via compatibility nft executor")
    }
    pub async fn extract_system_firewall() -> Result<FirewallConfig> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before system firewall extraction")?;

        let mut sock = NetlinkSocket::new();
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
            let key = (
                chain.family.clone(),
                chain.table.clone(),
                chain.name.clone(),
            );
            by_key.insert(
                key,
                FirewallChain {
                    name: chain.name,
                    table: chain.table,
                    family: chain.family,
                    priority: chain.priority,
                    r#type: chain.chain_type,
                    hook: chain.hook,
                    policy: chain.policy,
                    rules: Vec::new(),
                },
            );
        }

        for rule in rules {
            let key = (rule.family.clone(), rule.table.clone(), rule.chain.clone());
            let chain = by_key.entry(key).or_insert_with(|| FirewallChain {
                name: rule.chain.clone(),
                table: rule.table.clone(),
                family: rule.family.clone(),
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
                        name: zone_name,
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
        let families = ["inet", "ip", "ip6", "bridge", "netdev"];
        let mut out = Vec::new();

        for family in families {
            let mut h = NetfilterTransactionBuilder::msg_header(family);
            h.set_res_id(10);
            let request = nftables::Request::new().op_getchain_dump(&h);
            let mut iter = sock.request(&request).await?;

            while let Some(reply) = iter.recv().await {
                let (_, attrs) = reply?;
                let table = attrs
                    .get_table()
                    .map(cstr_to_string)
                    .unwrap_or_else(|_| String::new());
                let name = attrs
                    .get_name()
                    .map(cstr_to_string)
                    .unwrap_or_else(|_| String::new());
                if table.is_empty() || name.is_empty() {
                    continue;
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
                            .unwrap_or_else(|_| String::new());
                        let priority = hook_attrs
                            .get_priority()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|_| "0".to_string());
                        (hook, priority)
                    }
                    Err(_) => (String::new(), String::new()),
                };

                let policy = attrs
                    .get_policy()
                    .map(policy_num_to_name)
                    .unwrap_or_else(|_| String::new());

                out.push(DumpChain {
                    family: family.to_string(),
                    table,
                    name,
                    hook,
                    priority,
                    policy,
                    chain_type,
                });
            }
        }

        Ok(out)
    }

    async fn dump_rules(sock: &mut NetlinkSocket) -> Result<Vec<DumpRule>> {
        let families = ["inet", "ip", "ip6", "bridge", "netdev"];
        let mut out = Vec::new();

        for family in families {
            let mut h = NetfilterTransactionBuilder::msg_header(family);
            h.set_res_id(10);
            let request = nftables::Request::new().op_getrule_dump(&h);
            let mut iter = sock.request(&request).await?;

            while let Some(reply) = iter.recv().await {
                let (_, attrs) = reply?;
                let table = attrs
                    .get_table()
                    .map(cstr_to_string)
                    .unwrap_or_else(|_| String::new());
                let chain = attrs
                    .get_chain()
                    .map(cstr_to_string)
                    .unwrap_or_else(|_| String::new());
                if table.is_empty() || chain.is_empty() {
                    continue;
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
                    family: family.to_string(),
                    table,
                    chain,
                    position,
                    uuid,
                    parameters,
                });
            }
        }

        Ok(out)
    }
    #[cfg(test)]
    pub(crate) fn probe_compose_dumped_config() -> FirewallConfig {
        Self::compose_dumped_config(
            vec![
                DumpChain {
                    family: "inet".to_string(),
                    table: "opensnitch".to_string(),
                    name: "filter_input".to_string(),
                    hook: "input".to_string(),
                    priority: "0".to_string(),
                    policy: "accept".to_string(),
                    chain_type: "filter".to_string(),
                },
                DumpChain {
                    family: "inet".to_string(),
                    table: "opensnitch".to_string(),
                    name: "zone_wan_input".to_string(),
                    hook: "input".to_string(),
                    priority: "0".to_string(),
                    policy: "drop".to_string(),
                    chain_type: "filter".to_string(),
                },
            ],
            vec![
                DumpRule {
                    family: "inet".to_string(),
                    table: "opensnitch".to_string(),
                    chain: "filter_input".to_string(),
                    position: 1,
                    uuid: "ssh".to_string(),
                    parameters: "meta l4proto tcp".to_string(),
                },
                DumpRule {
                    family: "inet".to_string(),
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

        let mut socket = NetlinkSocket::new();
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
            chain: NetfilterRuleChain::FilterInput,
            expression: format!(
                "udp sport 53 queue num {queue_num}{bypass} comment \"opensnitch-queue-dns\""
            ),
            tag: INTERCEPTION_DNS_TAG.to_string(),
        });
        operations.push(FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NetfilterRuleChain::MangleOutput,
            expression: format!(
                "meta l4proto != tcp ct state new,related queue num {queue_num}{bypass} comment \"opensnitch-queue-connections-non-tcp\""
            ),
            tag: INTERCEPTION_NON_TCP_TAG.to_string(),
        });
        operations.push(FirewallNetlinkOperation::EnsureInterceptionRule {
            chain: NetfilterRuleChain::MangleOutput,
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
        for chain in &sysfw.chains {
            let family = FirewallNftablesAdapter::probe_family_or_default(chain).to_string();
            let table = FirewallNftablesAdapter::probe_table_or_default(chain).to_string();
            let name = FirewallNftablesAdapter::probe_chain_name_or_default(chain).to_string();
            let hook = if chain.hook.is_empty() {
                "output".to_string()
            } else {
                chain.hook.clone()
            };
            let policy = if chain.policy.is_empty() {
                "accept".to_string()
            } else {
                chain.policy.clone()
            };
            let priority = if chain.priority.is_empty() {
                "0".to_string()
            } else {
                chain.priority.clone()
            };
            let chain_type = chain_type_name(chain);

            operations.push(FirewallNetlinkOperation::EnsureSystemChain {
                family: family.clone(),
                table: table.clone(),
                name: name.clone(),
                hook,
                priority,
                policy,
                chain_type,
            });

            for rule in &chain.rules {
                if !rule.enabled {
                    continue;
                }

                let expression = FirewallNftablesAdapter::probe_nft_expression(rule, queue_num);
                if expression.is_empty() {
                    continue;
                }

                operations.push(FirewallNetlinkOperation::ApplySystemRule {
                    family: family.clone(),
                    table: table.clone(),
                    chain: name.clone(),
                    expression,
                    tag: FirewallNftablesAdapter::probe_rule_tag(chain, rule),
                });
            }
        }

        for zone in &sysfw.zones {
            for chain in &zone.chains {
                let family = FirewallNftablesAdapter::probe_family_or_default(chain).to_string();
                let table = FirewallNftablesAdapter::probe_table_or_default(chain).to_string();
                let name = FirewallNftablesAdapter::probe_chain_name_or_default(chain).to_string();
                let hook = if chain.hook.is_empty() {
                    "output".to_string()
                } else {
                    chain.hook.clone()
                };
                let policy = if chain.policy.is_empty() {
                    "accept".to_string()
                } else {
                    chain.policy.clone()
                };
                let priority = if chain.priority.is_empty() {
                    "0".to_string()
                } else {
                    chain.priority.clone()
                };
                let chain_type = chain_type_name(chain);

                operations.push(FirewallNetlinkOperation::EnsureSystemChain {
                    family: family.clone(),
                    table: table.clone(),
                    name: name.clone(),
                    hook,
                    priority,
                    policy,
                    chain_type,
                });

                for rule in &chain.rules {
                    if !rule.enabled {
                        continue;
                    }

                    let expression = FirewallNftablesAdapter::probe_nft_expression(rule, queue_num);
                    if expression.is_empty() {
                        continue;
                    }

                    operations.push(FirewallNetlinkOperation::ApplySystemRule {
                        family: family.clone(),
                        table: table.clone(),
                        chain: name.clone(),
                        expression,
                        tag: FirewallNftablesAdapter::probe_rule_tag(chain, rule),
                    });
                }
            }
        }

        operations
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
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };

        if fd < 0 {
            let errno = Errno::last();
            return Err(anyhow::anyhow!(
                "failed to open NETLINK_NETFILTER socket: {errno}"
            ));
        }

        let close_rc = unsafe { libc::close(fd) };
        if close_rc < 0 {
            let errno = Errno::last();
            return Err(anyhow::anyhow!(
                "failed to close NETLINK_NETFILTER probe socket: {errno}"
            ));
        }

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
        ParsedRuleExpression::parse_all(expression).is_some()
    }
    #[cfg(test)]
    pub(crate) fn probe_unsupported_expression_family(expression: &str) -> &'static str {
        unsupported_expression_family(expression)
    }
    #[cfg(test)]
    pub(crate) fn probe_unsupported_summary_for_ops(
        ops: &[FirewallNetlinkOperation],
    ) -> (Vec<&'static str>, Vec<(&'static str, usize)>) {
        unsupported_summary_for_ops(ops)
    }
}

impl GenerationId {
    async fn new_latest(sock: &mut NetlinkSocket) -> Result<Self> {
        let request = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
        let mut iter = sock.request(&request).await?;
        let (_, attrs) = iter.recv_one().await?;
        Ok(Self(attrs.get_id()?))
    }
}

fn chain_type_name(chain: &FirewallChain) -> String {
    match chain.r#type.as_str() {
        "mangle" if chain.hook.eq_ignore_ascii_case("output") => "route".to_string(),
        "mangle" => "filter".to_string(),
        "natdest" | "natsource" | "nat" => "nat".to_string(),
        "filter" => "filter".to_string(),
        _ => "filter".to_string(),
    }
}

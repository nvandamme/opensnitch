use anyhow::{Context, Result};
use netlink_bindings::nftables::{self, Nfgenmsg};
use netlink_socket2::NetlinkSocket;
use nix::errno::Errno;
use nix::libc;
use std::collections::BTreeMap;

use crate::models::firewall_config::{FirewallChain, FirewallConfig};
use crate::platform::adapters::firewall_nft::FirewallNftAdapter;
use crate::utils::conntrack::flush_conntrack_table;

#[cfg(test)]
use super::ParsedRuleExpression;
use super::{
    FirewallNftNetlinkAdapter, GenerationId, INTERCEPTION_DNS_TAG, INTERCEPTION_NON_TCP_TAG,
    INTERCEPTION_TCP_SYN_TAG, NetlinkExecutionSummary, NftNetlinkOperation, NftRuleChain,
    NftTransactionBuilder, TransactionOutcome,
};

impl NftNetlinkOperation {
    fn kind(&self) -> &'static str {
        match self {
            NftNetlinkOperation::EnsureBaseChains { .. } => "ensure_base_chains",
            NftNetlinkOperation::DisableBaseTable => "disable_base_table",
            NftNetlinkOperation::ValidateInterceptionRules => "validate_interception_rules",
            NftNetlinkOperation::EnsureInterceptionRule { .. } => "ensure_interception_rule",
            NftNetlinkOperation::EnsureSystemChain { .. } => "ensure_system_chain",
            NftNetlinkOperation::ApplySystemRule { .. } => "apply_system_rule",
            NftNetlinkOperation::ClearTaggedSystemRules { .. } => "clear_tagged_system_rules",
        }
    }
}

fn unsupported_expression_for_operation(op: &NftNetlinkOperation) -> Option<&str> {
    match op {
        NftNetlinkOperation::ApplySystemRule { expression, .. }
        | NftNetlinkOperation::EnsureInterceptionRule { expression, .. } => Some(expression),
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
    ops: &[NftNetlinkOperation],
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

impl FirewallNftNetlinkAdapter {
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
        FirewallNftAdapter::ensure(queue_num, queue_bypass)
            .await
            .context("execute ensure via compatibility nft executor")
    }

    pub async fn disable() -> Result<()> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before disable")?;

        let plan = vec![NftNetlinkOperation::DisableBaseTable];
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
        FirewallNftAdapter::disable()
            .await
            .context("execute disable via compatibility nft executor")
    }

    pub async fn interception_rules_valid() -> Result<bool> {
        Self::probe_netfilter_netlink_socket()
            .context("probe netfilter netlink socket before interception validation")?;

        let plan = vec![NftNetlinkOperation::ValidateInterceptionRules];
        let summary = Self::execute_plan_with_netlink(&plan)
            .await
            .context("execute netlink validation transaction")?;

        if matches!(summary.outcome, TransactionOutcome::Full) {
            return FirewallNftAdapter::interception_rules_valid()
                .await
                .context("validate interception rules after netlink execution");
        }

        tracing::debug!(
            ops = plan.len(),
            unsupported_ops = ?summary.unsupported_ops,
            unsupported_expression_families = ?summary.unsupported_expression_families,
            "nftables validation requires compatibility path"
        );
        FirewallNftAdapter::interception_rules_valid()
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
        FirewallNftAdapter::apply_system_firewall(sysfw, queue_num)
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
        FirewallNftAdapter::clear_system_firewall(sysfw)
            .await
            .context("execute system firewall clear via compatibility nft executor")
    }

    async fn execute_plan_with_netlink(
        ops: &[NftNetlinkOperation],
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
        let mut tx = NftTransactionBuilder::new(&mut socket, genid);

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

    fn plan_ensure(queue_num: u16, queue_bypass: bool) -> Vec<NftNetlinkOperation> {
        let mut operations = vec![NftNetlinkOperation::EnsureBaseChains {
            queue_num,
            queue_bypass,
        }];

        let bypass = if queue_bypass { " bypass" } else { "" };
        operations.push(NftNetlinkOperation::EnsureInterceptionRule {
            chain: NftRuleChain::FilterInput,
            expression: format!(
                "udp sport 53 queue num {queue_num}{bypass} comment \"opensnitch-queue-dns\""
            ),
            tag: INTERCEPTION_DNS_TAG.to_string(),
        });
        operations.push(NftNetlinkOperation::EnsureInterceptionRule {
            chain: NftRuleChain::MangleOutput,
            expression: format!(
                "meta l4proto != tcp ct state new,related queue num {queue_num}{bypass} comment \"opensnitch-queue-connections-non-tcp\""
            ),
            tag: INTERCEPTION_NON_TCP_TAG.to_string(),
        });
        operations.push(NftNetlinkOperation::EnsureInterceptionRule {
            chain: NftRuleChain::MangleOutput,
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
    ) -> Vec<NftNetlinkOperation> {
        if !sysfw.enabled {
            return Vec::new();
        }

        let mut operations = Vec::new();
        for chain in &sysfw.chains {
            let family = FirewallNftAdapter::probe_family_or_default(chain).to_string();
            let table = FirewallNftAdapter::probe_table_or_default(chain).to_string();
            let name = FirewallNftAdapter::probe_chain_name_or_default(chain).to_string();
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

            operations.push(NftNetlinkOperation::EnsureSystemChain {
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

                let expression = FirewallNftAdapter::probe_nft_expression(rule, queue_num);
                if expression.is_empty() {
                    continue;
                }

                operations.push(NftNetlinkOperation::ApplySystemRule {
                    family: family.clone(),
                    table: table.clone(),
                    chain: name.clone(),
                    expression,
                    tag: FirewallNftAdapter::probe_rule_tag(chain, rule),
                });
            }
        }

        operations
    }

    fn plan_clear_system_firewall(sysfw: &FirewallConfig) -> Vec<NftNetlinkOperation> {
        let mut operations = Vec::new();
        for chain in &sysfw.chains {
            operations.push(NftNetlinkOperation::ClearTaggedSystemRules {
                family: FirewallNftAdapter::probe_family_or_default(chain).to_string(),
                table: FirewallNftAdapter::probe_table_or_default(chain).to_string(),
                chain: FirewallNftAdapter::probe_chain_name_or_default(chain).to_string(),
            });
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_plan_ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Vec<NftNetlinkOperation> {
        Self::plan_ensure(queue_num, queue_bypass)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_plan_apply_system_firewall(
        sysfw: &FirewallConfig,
        queue_num: u16,
    ) -> Vec<NftNetlinkOperation> {
        Self::plan_apply_system_firewall(sysfw, queue_num)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_plan_clear_system_firewall(
        sysfw: &FirewallConfig,
    ) -> Vec<NftNetlinkOperation> {
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
        ops: &[NftNetlinkOperation],
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

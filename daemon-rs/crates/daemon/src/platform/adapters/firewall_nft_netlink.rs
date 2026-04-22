use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::libc;
use netlink_bindings::nftables::{self, Nfgenmsg};
use netlink_bindings::utils::{finalize_nested_header, push_header, push_nested_header, Rec};
use opensnitch_proto::pb;
use netlink_socket2::NetlinkSocket;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::platform::adapters::firewall_nft::FirewallNftAdapter;
use crate::utils::conntrack::flush_conntrack_table;

const SYSFW_TAG_PREFIX: &[u8] = b"opensnitch-sysfw:";
const INTERCEPTION_DNS_TAG: &str = "opensnitch-queue-dns";
const INTERCEPTION_NON_TCP_TAG: &str = "opensnitch-queue-connections-non-tcp";
const INTERCEPTION_TCP_SYN_TAG: &str = "opensnitch-queue-connections-tcp-syn";

const NFTA_EXPR_DATA: u16 = 2;
const NFTA_QUEUE_NUM: u16 = 1;
const NFTA_QUEUE_TOTAL: u16 = 2;
const NFTA_QUEUE_FLAGS: u16 = 3;
const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;

const CT_STATE_INVALID: u32 = 1;
const CT_STATE_ESTABLISHED: u32 = 2;
const CT_STATE_RELATED: u32 = 4;
const CT_STATE_NEW: u32 = 8;
const CT_STATE_UNTRACKED: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NftRuleChain {
    FilterInput,
    MangleOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NftNetlinkOperation {
    EnsureBaseChains {
        queue_num: u16,
        queue_bypass: bool,
    },
    DisableBaseTable,
    ValidateInterceptionRules,
    EnsureInterceptionRule {
        chain: NftRuleChain,
        expression: String,
        tag: String,
    },
    EnsureSystemChain {
        family: String,
        table: String,
        name: String,
        hook: String,
        priority: String,
        policy: String,
        chain_type: String,
    },
    ApplySystemRule {
        family: String,
        table: String,
        chain: String,
        expression: String,
        tag: String,
    },
    ClearTaggedSystemRules {
        family: String,
        table: String,
        chain: String,
    },
}

// This adapter owns netlink-oriented planning and compatibility checks.
// Unsupported operations intentionally return partial handling so the
// compatibility nft path can execute the remainder safely.
pub(crate) struct FirewallNftNetlinkAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GenerationId(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionOutcome {
    Full,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetlinkExecutionSummary {
    outcome: TransactionOutcome,
    unsupported_ops: Vec<&'static str>,
    unsupported_expression_families: Vec<(&'static str, usize)>,
}

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

    pub async fn apply_system_firewall(sysfw: &pb::SysFirewall, queue_num: u16) -> Result<()> {
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

    pub async fn clear_system_firewall(sysfw: &pb::SysFirewall) -> Result<()> {
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

    async fn execute_plan_with_netlink(ops: &[NftNetlinkOperation]) -> Result<NetlinkExecutionSummary> {
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
        sysfw: &pb::SysFirewall,
        queue_num: u16,
    ) -> Vec<NftNetlinkOperation> {
        if !sysfw.enabled {
            return Vec::new();
        }

        let mut operations = Vec::new();
        for item in &sysfw.system_rules {
            for chain in &item.chains {
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
        }

        operations
    }

    fn plan_clear_system_firewall(sysfw: &pb::SysFirewall) -> Vec<NftNetlinkOperation> {
        let mut operations = Vec::new();
        for item in &sysfw.system_rules {
            for chain in &item.chains {
                operations.push(NftNetlinkOperation::ClearTaggedSystemRules {
                    family: FirewallNftAdapter::probe_family_or_default(chain).to_string(),
                    table: FirewallNftAdapter::probe_table_or_default(chain).to_string(),
                    chain: FirewallNftAdapter::probe_chain_name_or_default(chain).to_string(),
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_plan_ensure(
        queue_num: u16,
        queue_bypass: bool,
    ) -> Vec<NftNetlinkOperation> {
        Self::plan_ensure(queue_num, queue_bypass)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_plan_apply_system_firewall(
        sysfw: &pb::SysFirewall,
        queue_num: u16,
    ) -> Vec<NftNetlinkOperation> {
        Self::plan_apply_system_firewall(sysfw, queue_num)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_plan_clear_system_firewall(
        sysfw: &pb::SysFirewall,
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

struct NftTransactionBuilder {
    inner: nftables::Chained<'static>,
    has_operation: bool,
}

impl NftTransactionBuilder {
    fn new(sock: &mut NetlinkSocket, genid: GenerationId) -> Self {
        let seq = sock.reserve_seq(256);
        let mut inner = nftables::Chained::new(seq);
        inner
            .request()
            .op_batch_begin_do(&Self::batch_header())
            .encode()
            .push_genid(genid.0);
        Self {
            inner,
            has_operation: false,
        }
    }

    fn is_empty(&self) -> bool {
        !self.has_operation
    }

    async fn apply_operation(
        &mut self,
        sock: &mut NetlinkSocket,
        op: &NftNetlinkOperation,
    ) -> Result<bool> {
        match op {
            NftNetlinkOperation::EnsureBaseChains { .. } => {
                self.ensure_base_chains();
                Ok(true)
            }
            NftNetlinkOperation::DisableBaseTable => {
                self.delete_table("inet", "opensnitch");
                Ok(true)
            }
            NftNetlinkOperation::EnsureSystemChain {
                family,
                table,
                name,
                hook,
                priority,
                policy,
                chain_type,
            } => {
                self.ensure_table(family, table);
                self.ensure_base_chain(family, table, name, hook, priority, policy, chain_type)?;
                Ok(true)
            }
            NftNetlinkOperation::ApplySystemRule {
                family,
                table,
                chain,
                expression,
                tag,
            } => {
                if self
                    .has_rule_with_userdata(sock, family, table, chain, tag.as_bytes())
                    .await?
                {
                    return Ok(true);
                }

                let supported = self.add_system_rule(family, table, chain, expression, tag);
                if !supported {
                    tracing::debug!(
                        family,
                        table,
                        chain,
                        expression,
                        "system rule expression is not yet netlink-supported; delegating to CLI fallback"
                    );
                }
                Ok(supported)
            }
            NftNetlinkOperation::ClearTaggedSystemRules {
                family,
                table,
                chain,
            } => self.clear_tagged_system_rules(sock, family, table, chain).await,
            NftNetlinkOperation::ValidateInterceptionRules => self.validate_interception_rules(sock).await,
            NftNetlinkOperation::EnsureInterceptionRule {
                chain,
                expression,
                tag,
            } => {
                let (family, table, chain_name) = match chain {
                    NftRuleChain::FilterInput => ("inet", "opensnitch", "filter_input"),
                    NftRuleChain::MangleOutput => ("inet", "opensnitch", "mangle_output"),
                };

                if self
                    .has_rule_with_userdata(sock, family, table, chain_name, tag.as_bytes())
                    .await?
                {
                    return Ok(true);
                }

                let supported = self.add_system_rule(family, table, chain_name, expression, tag);
                if !supported {
                    tracing::debug!(
                        family,
                        table,
                        chain = chain_name,
                        expression,
                        "interception rule expression is not yet netlink-supported; delegating to CLI fallback"
                    );
                }
                Ok(supported)
            }
        }
    }

    async fn commit(mut self, sock: &mut NetlinkSocket) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }

        self.inner.request().op_batch_end_do(&Self::batch_header());
        let chained = self.inner.finalize();
        sock.request_chained(&chained).await?.recv_all().await?;
        Ok(())
    }

    fn ensure_base_chains(&mut self) {
        self.ensure_table("inet", "opensnitch");
        let _ = self.ensure_base_chain(
            "inet",
            "opensnitch",
            "filter_input",
            "input",
            "0",
            "accept",
            "filter",
        );
        let _ = self.ensure_base_chain(
            "inet",
            "opensnitch",
            "mangle_output",
            "output",
            "0",
            "accept",
            "route",
        );
    }

    fn ensure_table(&mut self, family: &str, table: &str) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .set_create()
            .op_newtable_do(&h)
            .encode()
            .push_name_bytes(table.as_bytes());
        self.has_operation = true;
    }

    fn ensure_base_chain(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        hook: &str,
        priority: &str,
        policy: &str,
        chain_type: &str,
    ) -> Result<()> {
        let hook_num = chain_hook_num(hook)
            .with_context(|| format!("unsupported nft hook: {hook}"))?;
        let priority = chain_priority(priority)?;
        let policy = chain_policy(policy)
            .with_context(|| format!("unsupported nft policy: {policy}"))?;

        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .set_create()
            .op_newchain_do(&h)
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_name_bytes(chain.as_bytes())
            .nested_hook()
            .push_num(hook_num)
            .push_priority(priority)
            .end_nested()
            .push_policy(policy)
            .push_type_bytes(chain_type.as_bytes())
            .push_flags(nftables::ChainFlags::Base as u32);
        self.has_operation = true;
        Ok(())
    }

    fn delete_table(&mut self, family: &str, table: &str) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .op_deltable_do(&h)
            .encode()
            .push_name_bytes(table.as_bytes());
        self.has_operation = true;
    }

    fn add_system_rule(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        expression: &str,
        tag: &str,
    ) -> bool {
        let parsed_rules = match ParsedRuleExpression::parse_all(expression) {
            Some(parsed) => parsed,
            None => return false,
        };

        for parsed in parsed_rules {
            self.add_parsed_rule(family, table, chain, &parsed, tag);
        }

        true
    }

    fn add_parsed_rule(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        parsed: &ParsedRuleExpression,
        tag: &str,
    ) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = self
            .inner
            .request()
            .set_create()
            .op_newrule_do(&h);
        let mut exprs = request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes())
            .push_userdata(tag.as_bytes())
            .nested_expressions();

        for cond in &parsed.conditions {
            match cond {
                RuleCondition::MetaL4Proto { op, proto } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_meta()
                        .push_key(nftables::MetaKeys::L4Proto as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                    RuleCondition::MetaMark { op, mark } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_meta()
                        .push_key(nftables::MetaKeys::Mark as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&mark.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                    RuleCondition::IpProtocol { op, proto } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(9)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                    RuleCondition::Ip6NextHeader { op, proto } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(6)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                    RuleCondition::Ipv4Addr { op, offset, addr } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(4)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&addr.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                    RuleCondition::Ipv6Addr { op, offset, addr } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(16)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&addr.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv4AddrRange { op, offset, start, end } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(4)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_range()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_from_data()
                        .push_value(&start.octets())
                        .end_nested()
                        .nested_to_data()
                        .push_value(&end.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv4AddrCidr {
                    op,
                    offset,
                    mask,
                    value,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(4)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(4)
                        .nested_mask()
                        .push_value(&mask.to_be_bytes())
                        .end_nested()
                        .nested_xor()
                        .push_value(&0_u32.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&value.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv6AddrRange { op, offset, start, end } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(16)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_range()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_from_data()
                        .push_value(&start.octets())
                        .end_nested()
                        .nested_to_data()
                        .push_value(&end.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv6AddrCidr {
                    op,
                    offset,
                    mask,
                    value,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(16)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(16)
                        .nested_mask()
                        .push_value(mask)
                        .end_nested()
                        .nested_xor()
                        .push_value(&[0_u8; 16])
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(value)
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::CtStateMask { mask } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_ct()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_key(nftables::CtKeys::State as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(4)
                        .nested_mask()
                        .push_value(&mask.to_be_bytes())
                        .end_nested()
                        .nested_xor()
                        .push_value(&0_u32.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Neq as u32)
                        .nested_data()
                        .push_value(&0_u32.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::TcpSynFlags => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(13)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(1)
                        .nested_mask()
                        .push_value(&[0x17])
                        .end_nested()
                        .nested_xor()
                        .push_value(&[0x00])
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Eq as u32)
                        .nested_data()
                        .push_value(&[0x02])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::TransportPort { op, offset, port } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(*offset)
                        .push_len(2)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&port.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::TransportPortRange { op, offset, start, end } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(*offset)
                        .push_len(2)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_range()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_from_data()
                        .push_value(&start.to_be_bytes())
                        .end_nested()
                        .nested_to_data()
                        .push_value(&end.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::IcmpType { proto, type_code } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_meta()
                        .push_key(nftables::MetaKeys::L4Proto as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Eq as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(0)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Eq as u32)
                        .nested_data()
                        .push_value(&[*type_code])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
            }
        }

        match parsed.action {
            RuleAction::Verdict(verdict) => {
                let verdict = match verdict {
                    RuleVerdict::Accept => nftables::VerdictCode::Accept,
                    RuleVerdict::Drop => nftables::VerdictCode::Drop,
                };
                exprs = exprs
                    .nested_elem()
                    .nested_data_immediate()
                    .push_dreg(nftables::Registers::RegVerdict as u32)
                    .nested_data()
                    .nested_verdict()
                    .push_code(verdict as u32)
                    .end_nested()
                    .end_nested()
                    .end_nested()
                    .end_nested();
            }
            RuleAction::Queue { num, bypass } => {
                exprs = push_queue_expression(exprs, num, bypass);
            }
        }

        let _ = exprs.end_nested();

        self.has_operation = true;
    }

    async fn clear_tagged_system_rules(
        &mut self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
    ) -> Result<bool> {
        let handles = self
            .list_tagged_rule_handles(sock, family, table, chain)
            .await
            .context("list tagged system rule handles")?;
        for handle in handles {
            self.delete_rule(family, table, chain, handle);
        }
        Ok(true)
    }

    async fn has_rule_with_userdata(
        &self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
        userdata: &[u8],
    ) -> Result<bool> {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = nftables::Request::new().op_getrule_dump(&h);
        request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes());

        let mut iter = sock.request(&request).await?;
        while let Some(reply) = iter.recv().await {
            let (_, attrs) = reply?;
            if let Ok(existing) = attrs.get_userdata() {
                if existing == userdata {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn validate_interception_rules(&self, sock: &mut NetlinkSocket) -> Result<bool> {
        let dns = self
            .count_rules_with_userdata(sock, "inet", "opensnitch", "filter_input", INTERCEPTION_DNS_TAG.as_bytes())
            .await?;
        let non_tcp = self
            .count_rules_with_userdata(sock, "inet", "opensnitch", "mangle_output", INTERCEPTION_NON_TCP_TAG.as_bytes())
            .await?;
        let tcp_syn = self
            .count_rules_with_userdata(sock, "inet", "opensnitch", "mangle_output", INTERCEPTION_TCP_SYN_TAG.as_bytes())
            .await?;

        Ok(dns == 1 && non_tcp == 1 && tcp_syn == 1)
    }

    async fn count_rules_with_userdata(
        &self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
        userdata: &[u8],
    ) -> Result<usize> {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = nftables::Request::new().op_getrule_dump(&h);
        request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes());

        let mut count = 0;
        let mut iter = sock.request(&request).await?;
        while let Some(reply) = iter.recv().await {
            let (_, attrs) = reply?;
            if let Ok(existing) = attrs.get_userdata() {
                if existing == userdata {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    async fn list_tagged_rule_handles(
        &self,
        sock: &mut NetlinkSocket,
        family: &str,
        table: &str,
        chain: &str,
    ) -> Result<Vec<u64>> {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = nftables::Request::new().op_getrule_dump(&h);
        request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes());

        let mut iter = sock.request(&request).await?;
        let mut handles = Vec::new();
        while let Some(reply) = iter.recv().await {
            let (_, attrs) = reply?;
            let userdata = match attrs.get_userdata() {
                Ok(userdata) => userdata,
                Err(_) => continue,
            };
            if userdata.starts_with(SYSFW_TAG_PREFIX) {
                if let Ok(handle) = attrs.get_handle() {
                    handles.push(handle);
                }
            }
        }

        Ok(handles)
    }

    fn delete_rule(&mut self, family: &str, table: &str, chain: &str, handle: u64) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        self.inner
            .request()
            .op_delrule_do(&h)
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes())
            .push_handle(handle);
        self.has_operation = true;
    }

    fn batch_header() -> Nfgenmsg {
        let mut h = Nfgenmsg::new();
        h.set_res_id(10);
        h
    }

    fn msg_header(family: &str) -> Nfgenmsg {
        Nfgenmsg {
            nfgen_family: family_to_af(family),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleVerdict {
    Accept,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Verdict(RuleVerdict),
    Queue { num: u16, bypass: bool },
}

#[derive(Debug, Clone, Copy)]
enum RuleCondition {
    MetaL4Proto {
        op: nftables::CmpOps,
        proto: u8,
    },
    MetaMark {
        op: nftables::CmpOps,
        mark: u32,
    },
    IpProtocol {
        op: nftables::CmpOps,
        proto: u8,
    },
    Ip6NextHeader {
        op: nftables::CmpOps,
        proto: u8,
    },
    Ipv4Addr {
        op: nftables::CmpOps,
        offset: u32,
        addr: Ipv4Addr,
    },
    Ipv4AddrRange {
        op: nftables::RangeOps,
        offset: u32,
        start: Ipv4Addr,
        end: Ipv4Addr,
    },
    Ipv4AddrCidr {
        op: nftables::CmpOps,
        offset: u32,
        mask: u32,
        value: u32,
    },
    Ipv6Addr {
        op: nftables::CmpOps,
        offset: u32,
        addr: Ipv6Addr,
    },
    Ipv6AddrRange {
        op: nftables::RangeOps,
        offset: u32,
        start: Ipv6Addr,
        end: Ipv6Addr,
    },
    Ipv6AddrCidr {
        op: nftables::CmpOps,
        offset: u32,
        mask: [u8; 16],
        value: [u8; 16],
    },
    CtStateMask {
        mask: u32,
    },
    TcpSynFlags,
    TransportPort {
        op: nftables::CmpOps,
        offset: u32,
        port: u16,
    },
    TransportPortRange {
        op: nftables::RangeOps,
        offset: u32,
        start: u16,
        end: u16,
    },
    IcmpType {
        proto: u8,
        type_code: u8,
    },
}

#[derive(Debug, Clone)]
struct ParsedRuleExpression {
    conditions: Vec<RuleCondition>,
    action: RuleAction,
}

impl ParsedRuleExpression {
    fn parse_all(expression: &str) -> Option<Vec<Self>> {
        let tokens: Vec<&str> = expression.split_whitespace().collect();
        if tokens.is_empty() {
            return None;
        }

        let mut expansions: Vec<Vec<RuleCondition>> = vec![Vec::new()];
        let mut i = 0;
        let end = tokens.len();
        while i < end {
            match tokens[i] {
                "accept" => {
                    let action = RuleAction::Verdict(RuleVerdict::Accept);
                    return finish_expansions(expansions, action, &tokens, i + 1);
                }
                "drop" => {
                    let action = RuleAction::Verdict(RuleVerdict::Drop);
                    return finish_expansions(expansions, action, &tokens, i + 1);
                }
                "queue" => {
                    let (action, next) = parse_queue_action(&tokens, i)?;
                    return finish_expansions(expansions, action, &tokens, next);
                }
                _ => {}
            }

            if i + 2 < end && tokens[i] == "meta" && tokens[i + 1] == "l4proto" {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let (values, next) = parse_value_list(&tokens, value_idx, end)?;
                let mut next_expansions = Vec::new();
                for value in values {
                    let proto = parse_proto(value)?;
                    for current in &expansions {
                        let mut updated = current.clone();
                        updated.push(RuleCondition::MetaL4Proto { op, proto });
                        next_expansions.push(updated);
                    }
                }
                expansions = next_expansions;
                i = next;
                continue;
            }

            if i + 2 < end && tokens[i] == "meta" && tokens[i + 1] == "mark" {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let mark = parse_u32_token(tokens[value_idx])?;
                push_condition(&mut expansions, RuleCondition::MetaMark { op, mark });
                i = value_idx + 1;
                continue;
            }

            if i + 2 < end && tokens[i] == "ip" && tokens[i + 1] == "protocol" {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let (values, next) = parse_value_list(&tokens, value_idx, end)?;
                let mut next_expansions = Vec::new();
                for value in values {
                    let proto = parse_proto(value)?;
                    for current in &expansions {
                        let mut updated = current.clone();
                        updated.push(RuleCondition::IpProtocol { op, proto });
                        next_expansions.push(updated);
                    }
                }
                expansions = next_expansions;
                i = next;
                continue;
            }

            if i + 2 < end
                && tokens[i] == "ip"
                && (tokens[i + 1] == "saddr" || tokens[i + 1] == "daddr")
            {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let offset = if tokens[i + 1] == "saddr" { 12 } else { 16 };
                let value = tokens[value_idx];
                if let Some((start, end_addr)) = parse_ipv4_range(value) {
                    let range_op = cmp_to_range_op(op)?;
                    push_condition(
                        &mut expansions,
                        RuleCondition::Ipv4AddrRange {
                            op: range_op,
                            offset,
                            start,
                            end: end_addr,
                        },
                    );
                } else if let Some((network, mask)) = parse_ipv4_cidr(value) {
                    push_condition(
                        &mut expansions,
                        RuleCondition::Ipv4AddrCidr {
                            op,
                            offset,
                            mask,
                            value: u32::from(network),
                        },
                    );
                } else {
                    let addr = value.parse::<Ipv4Addr>().ok()?;
                    push_condition(&mut expansions, RuleCondition::Ipv4Addr { op, offset, addr });
                }
                i = value_idx + 1;
                continue;
            }

            if i + 2 < end && tokens[i] == "ip6" && tokens[i + 1] == "nexthdr" {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let (values, next) = parse_value_list(&tokens, value_idx, end)?;
                let mut next_expansions = Vec::new();
                for value in values {
                    let proto = parse_proto(value)?;
                    for current in &expansions {
                        let mut updated = current.clone();
                        updated.push(RuleCondition::Ip6NextHeader { op, proto });
                        next_expansions.push(updated);
                    }
                }
                expansions = next_expansions;
                i = next;
                continue;
            }

            if i + 2 < end
                && tokens[i] == "ip6"
                && (tokens[i + 1] == "saddr" || tokens[i + 1] == "daddr")
            {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let offset = if tokens[i + 1] == "saddr" { 8 } else { 24 };
                let value = tokens[value_idx];
                if let Some((start, end_addr)) = parse_ipv6_range(value) {
                    let range_op = cmp_to_range_op(op)?;
                    push_condition(
                        &mut expansions,
                        RuleCondition::Ipv6AddrRange {
                            op: range_op,
                            offset,
                            start,
                            end: end_addr,
                        },
                    );
                } else if let Some((network, mask)) = parse_ipv6_cidr(value) {
                    push_condition(
                        &mut expansions,
                        RuleCondition::Ipv6AddrCidr {
                            op,
                            offset,
                            mask,
                            value: network,
                        },
                    );
                } else {
                    let addr = value.parse::<Ipv6Addr>().ok()?;
                    push_condition(&mut expansions, RuleCondition::Ipv6Addr { op, offset, addr });
                }
                i = value_idx + 1;
                continue;
            }

            if i + 2 < end
                && tokens[i] == "th"
                && (tokens[i + 1] == "dport" || tokens[i + 1] == "sport")
            {
                let (op, value_idx) = parse_cmp_and_value_index(&tokens, i + 2, end)?;
                let offset = if tokens[i + 1] == "sport" { 0 } else { 2 };
                let value = tokens[value_idx];
                if let Some((start, end_port)) = parse_port_range(value) {
                    let range_op = cmp_to_range_op(op)?;
                    push_condition(
                        &mut expansions,
                        RuleCondition::TransportPortRange {
                            op: range_op,
                            offset,
                            start,
                            end: end_port,
                        },
                    );
                } else {
                    let port = value.parse::<u16>().ok()?;
                    push_condition(&mut expansions, RuleCondition::TransportPort { op, offset, port });
                }
                i = value_idx + 1;
                continue;
            }

            if i + 2 < end
                && (tokens[i] == "tcp" || tokens[i] == "udp")
                && (tokens[i + 1] == "dport" || tokens[i + 1] == "sport")
            {
                let proto = parse_proto(tokens[i])?;
                push_condition(
                    &mut expansions,
                    RuleCondition::MetaL4Proto {
                        op: nftables::CmpOps::Eq,
                        proto,
                    },
                );

                let value = tokens[i + 2];
                let offset = if tokens[i + 1] == "sport" { 0 } else { 2 };
                if let Some((start, end_port)) = parse_port_range(value) {
                    push_condition(
                        &mut expansions,
                        RuleCondition::TransportPortRange {
                            op: nftables::RangeOps::Eq,
                            offset,
                            start,
                            end: end_port,
                        },
                    );
                } else {
                    let port = value.parse::<u16>().ok()?;
                    push_condition(
                        &mut expansions,
                        RuleCondition::TransportPort {
                            op: nftables::CmpOps::Eq,
                            offset,
                            port,
                        },
                    );
                }
                i += 3;
                continue;
            }

            if i + 2 < end && (tokens[i] == "icmp" || tokens[i] == "icmpv6") && tokens[i + 1] == "type" {
                let proto = parse_proto(tokens[i])?;
                let (values, next) = parse_value_list(&tokens, i + 2, end)?;
                let mut next_expansions = Vec::new();
                for value in values {
                    let type_code = parse_icmp_type(tokens[i] == "icmpv6", value)?;
                    for current in &expansions {
                        let mut updated = current.clone();
                        updated.push(RuleCondition::IcmpType { proto, type_code });
                        next_expansions.push(updated);
                    }
                }
                expansions = next_expansions;
                i = next;
                continue;
            }

            if i + 2 < end && tokens[i] == "ct" && tokens[i + 1] == "state" {
                let states = tokens[i + 2]
                    .split(',')
                    .map(str::trim)
                    .filter(|state| !state.is_empty());
                let mut mask = 0_u32;
                for state in states {
                    mask |= ct_state_mask(state)?;
                }
                if mask == 0 {
                    return None;
                }
                push_condition(&mut expansions, RuleCondition::CtStateMask { mask });
                i += 3;
                continue;
            }

            if i + 5 < end
                && tokens[i] == "tcp"
                && tokens[i + 1] == "flags"
                && tokens[i + 2] == "&"
                && tokens[i + 3] == "(fin|syn|rst|ack)"
                && tokens[i + 4] == "=="
                && tokens[i + 5] == "syn"
            {
                push_condition(&mut expansions, RuleCondition::TcpSynFlags);
                i += 6;
                continue;
            }

            return None;
        }

        None
    }
}

fn parse_cmp_and_value_index(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(nftables::CmpOps, usize)> {
    if start >= end {
        return None;
    }

    match tokens[start] {
        "==" if start + 1 < end => Some((nftables::CmpOps::Eq, start + 1)),
        "!=" if start + 1 < end => Some((nftables::CmpOps::Neq, start + 1)),
        "==" | "!=" => None,
        _ => Some((nftables::CmpOps::Eq, start)),
    }
}

fn finish_expansions(
    expansions: Vec<Vec<RuleCondition>>,
    action: RuleAction,
    tokens: &[&str],
    next: usize,
) -> Option<Vec<ParsedRuleExpression>> {
    if next < tokens.len() {
        if tokens[next] != "comment" {
            return None;
        }
    }

    Some(
        expansions
            .into_iter()
            .map(|conditions| ParsedRuleExpression { conditions, action })
            .collect(),
    )
}

fn push_condition(expansions: &mut Vec<Vec<RuleCondition>>, condition: RuleCondition) {
    for current in expansions.iter_mut() {
        current.push(condition);
    }
}

fn parse_value_list<'a>(tokens: &'a [&'a str], start: usize, end: usize) -> Option<(Vec<&'a str>, usize)> {
    if start >= end {
        return None;
    }

    if tokens[start] != "{" {
        return Some((vec![trim_trailing_comma(tokens[start])], start + 1));
    }

    let mut values = Vec::new();
    let mut index = start + 1;
    while index < end {
        let token = trim_trailing_comma(tokens[index]);
        if token == "}" {
            return Some((values, index + 1));
        }
        values.push(token);
        index += 1;
    }

    None
}

fn trim_trailing_comma(token: &str) -> &str {
    token.trim_end_matches(',')
}

fn parse_queue_action(tokens: &[&str], start: usize) -> Option<(RuleAction, usize)> {
    let mut index = start + 1;
    let mut queue_num = 0_u16;
    let mut bypass = false;

    while index < tokens.len() {
        match tokens[index] {
            "num" if index + 1 < tokens.len() => {
                queue_num = tokens[index + 1].parse::<u16>().ok()?;
                index += 2;
            }
            "bypass" => {
                bypass = true;
                index += 1;
            }
            "comment" => break,
            _ => return None,
        }
    }

    Some((RuleAction::Queue { num: queue_num, bypass }, index))
}

fn parse_proto(token: &str) -> Option<u8> {
    match token {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        _ => token.parse::<u8>().ok(),
    }
}

fn parse_u32_token(token: &str) -> Option<u32> {
    if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        token.parse::<u32>().ok()
    }
}

fn parse_ipv4_range(token: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (start, end) = token.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?))
}

fn parse_ipv4_cidr(token: &str) -> Option<(Ipv4Addr, u32)> {
    let (addr_part, prefix_part) = token.split_once('/')?;
    let addr = addr_part.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix_part.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = ipv4_cidr_mask(prefix);
    let network = Ipv4Addr::from(u32::from(addr) & mask);
    Some((network, mask))
}

fn ipv4_cidr_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    u32::MAX << (32 - prefix)
}

fn parse_ipv6_range(token: &str) -> Option<(Ipv6Addr, Ipv6Addr)> {
    let (start, end) = token.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?))
}

fn parse_ipv6_cidr(token: &str) -> Option<([u8; 16], [u8; 16])> {
    let (addr_part, prefix_part) = token.split_once('/')?;
    let addr = addr_part.parse::<Ipv6Addr>().ok()?;
    let prefix = prefix_part.parse::<u8>().ok()?;
    if prefix > 128 {
        return None;
    }

    let mask_u128 = ipv6_cidr_mask(prefix);
    let addr_u128 = u128::from_be_bytes(addr.octets());
    let network_u128 = addr_u128 & mask_u128;

    Some((network_u128.to_be_bytes(), mask_u128.to_be_bytes()))
}

fn ipv6_cidr_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    u128::MAX << (128 - prefix)
}

fn parse_port_range(token: &str) -> Option<(u16, u16)> {
    let (start, end) = token.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?))
}

fn cmp_to_range_op(op: nftables::CmpOps) -> Option<nftables::RangeOps> {
    match op {
        nftables::CmpOps::Eq => Some(nftables::RangeOps::Eq),
        nftables::CmpOps::Neq => Some(nftables::RangeOps::Neq),
        _ => None,
    }
}

fn ct_state_mask(state: &str) -> Option<u32> {
    match state {
        "invalid" => Some(CT_STATE_INVALID),
        "established" => Some(CT_STATE_ESTABLISHED),
        "related" => Some(CT_STATE_RELATED),
        "new" => Some(CT_STATE_NEW),
        "untracked" => Some(CT_STATE_UNTRACKED),
        _ => None,
    }
}

fn parse_icmp_type(is_v6: bool, token: &str) -> Option<u8> {
    Some(match (is_v6, token) {
        (false, "echo-reply") => 0,
        (false, "destination-unreachable") => 3,
        (false, "source-quench") => 4,
        (false, "redirect") => 5,
        (false, "echo-request") => 8,
        (false, "router-advertisement") => 9,
        (false, "router-solicitation") => 10,
        (false, "time-exceeded") => 11,
        (false, "parameter-problem") => 12,
        (false, "timestamp-request") => 13,
        (false, "timestamp-reply") => 14,
        (false, "info-request") => 15,
        (false, "info-reply") => 16,
        (false, "address-mask-request") => 17,
        (false, "address-mask-reply") => 18,
        (true, "destination-unreachable") => 1,
        (true, "packet-too-big") => 2,
        (true, "time-exceeded") => 3,
        (true, "parameter-problem") => 4,
        (true, "echo-request") => 128,
        (true, "echo-reply") => 129,
        (true, "router-solicitation") => 133,
        (true, "router-advertisement") => 134,
        (true, "neighbour-solicitation") => 135,
        (true, "neighbour-advertisement") => 136,
        (true, "redirect") => 137,
        _ => return None,
    })
}

fn chain_type_name(chain: &pb::FwChain) -> String {
    match chain.r#type.as_str() {
        "mangle" if chain.hook.eq_ignore_ascii_case("output") => "route".to_string(),
        "mangle" => "filter".to_string(),
        "natdest" | "natsource" | "nat" => "nat".to_string(),
        "filter" => "filter".to_string(),
        _ => "filter".to_string(),
    }
}

fn chain_hook_num(hook: &str) -> Option<u32> {
    Some(match hook.to_ascii_lowercase().as_str() {
        "prerouting" => libc::NF_INET_PRE_ROUTING as u32,
        "input" => libc::NF_INET_LOCAL_IN as u32,
        "forward" => libc::NF_INET_FORWARD as u32,
        "output" => libc::NF_INET_LOCAL_OUT as u32,
        "postrouting" => libc::NF_INET_POST_ROUTING as u32,
        "ingress" => libc::NF_INET_INGRESS as u32,
        _ => return None,
    })
}

fn chain_priority(priority: &str) -> Result<i32> {
    if let Ok(value) = priority.parse::<i32>() {
        return Ok(value);
    }

    Ok(match priority.to_ascii_lowercase().as_str() {
        "" => 0,
        "raw" => libc::NF_IP_PRI_RAW,
        "conntrack" => libc::NF_IP_PRI_CONNTRACK,
        "mangle" => libc::NF_IP_PRI_MANGLE,
        "natdest" | "dnat" => libc::NF_IP_PRI_NAT_DST,
        "filter" => libc::NF_IP_PRI_FILTER,
        "security" => libc::NF_IP_PRI_SECURITY,
        "natsource" | "snat" => libc::NF_IP_PRI_NAT_SRC,
        other => anyhow::bail!("unsupported nft priority: {other}"),
    })
}

fn chain_policy(policy: &str) -> Option<u32> {
    match policy.to_ascii_lowercase().as_str() {
        "accept" => Some(nftables::VerdictCode::Accept as u32),
        "drop" => Some(nftables::VerdictCode::Drop as u32),
        _ => None,
    }
}

fn push_queue_expression<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    queue_num: u16,
    bypass: bool,
) -> nftables::PushExprListAttrs<Prev> {
    let mut expr = exprs.nested_elem().push_name_bytes(b"queue");
    let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

    push_header(expr.as_rec_mut(), NFTA_QUEUE_NUM, 2);
    expr.as_rec_mut().extend(queue_num.to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_QUEUE_TOTAL, 2);
    expr.as_rec_mut().extend(1_u16.to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_QUEUE_FLAGS, 2);
    let flags = if bypass { NFT_QUEUE_FLAG_BYPASS } else { 0 };
    expr.as_rec_mut().extend(flags.to_be_bytes());

    finalize_nested_header(expr.as_rec_mut(), data_offset);
    expr.end_nested()
}

fn family_to_af(family: &str) -> u8 {
    match family {
        "ip" => libc::AF_INET as u8,
        "ip6" => libc::AF_INET6 as u8,
        "inet" => libc::AF_INET as u8,
        "bridge" => libc::AF_BRIDGE as u8,
        "netdev" => libc::AF_UNSPEC as u8,
        _ => libc::AF_INET as u8,
    }
}

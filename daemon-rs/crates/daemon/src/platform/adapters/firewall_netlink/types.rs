use netlink_bindings::nftables;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const SYSFW_TAG_PREFIX: &[u8] = b"opensnitch-sysfw:";
pub(super) const INTERCEPTION_DNS_TAG: &str = "opensnitch-queue-dns";
pub(super) const INTERCEPTION_NON_TCP_TAG: &str = "opensnitch-queue-connections-non-tcp";
pub(super) const INTERCEPTION_TCP_SYN_TAG: &str = "opensnitch-queue-connections-tcp-syn";

pub(super) const NFTA_EXPR_DATA: u16 = 2;
pub(super) const NFTA_QUEUE_NUM: u16 = 1;
pub(super) const NFTA_QUEUE_TOTAL: u16 = 2;
pub(super) const NFTA_QUEUE_FLAGS: u16 = 3;
pub(super) const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;

pub(super) const CT_STATE_INVALID: u32 = 1;
pub(super) const CT_STATE_ESTABLISHED: u32 = 2;
pub(super) const CT_STATE_RELATED: u32 = 4;
pub(super) const CT_STATE_NEW: u32 = 8;
pub(super) const CT_STATE_UNTRACKED: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetfilterRuleChain {
    FilterInput,
    MangleOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirewallNetlinkOperation {
    EnsureBaseChains {
        queue_num: u16,
        queue_bypass: bool,
    },
    DisableBaseTable,
    ValidateInterceptionRules,
    EnsureInterceptionRule {
        chain: NetfilterRuleChain,
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
pub(crate) struct FirewallNetlinkAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GenerationId(pub(super) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransactionOutcome {
    Full,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetlinkExecutionSummary {
    pub(super) outcome: TransactionOutcome,
    pub(super) unsupported_ops: Vec<&'static str>,
    pub(super) unsupported_expression_families: Vec<(&'static str, usize)>,
}

pub(super) struct NetfilterTransactionBuilder {
    pub(super) inner: nftables::Chained<'static>,
    pub(super) has_operation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleVerdict {
    Accept,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuleAction {
    Verdict(RuleVerdict),
    Queue { num: u16, bypass: bool },
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RuleCondition {
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
pub(super) struct ParsedRuleExpression {
    pub(super) conditions: Vec<RuleCondition>,
    pub(super) action: RuleAction,
}

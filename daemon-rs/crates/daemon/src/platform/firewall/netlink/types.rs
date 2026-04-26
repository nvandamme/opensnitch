use netlink_bindings::nftables;
use std::error::Error;
use std::fmt;

use super::{NftChain, NftRule, NftTable};

pub(super) const NFTA_EXPR_DATA: u16 = 2;
pub(super) const NFTA_QUEUE_NUM: u16 = 1;
pub(super) const NFTA_QUEUE_TOTAL: u16 = 2;
pub(super) const NFTA_QUEUE_FLAGS: u16 = 3;
pub(super) const NFTA_MASQ_FLAGS: u16 = 1;
pub(super) const NFTA_MASQ_REG_PROTO_MIN: u16 = 2;
pub(super) const NFTA_MASQ_REG_PROTO_MAX: u16 = 3;
pub(super) const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
pub(super) const NFTA_REDIR_REG_PROTO_MAX: u16 = 2;
pub(super) const NFTA_REDIR_FLAGS: u16 = 3;
pub(super) const NFTA_LIMIT_RATE: u16 = 1;
pub(super) const NFTA_LIMIT_UNIT: u16 = 2;
pub(super) const NFTA_LIMIT_BURST: u16 = 3;
pub(super) const NFTA_LIMIT_TYPE: u16 = 4;
pub(super) const NFTA_LIMIT_FLAGS: u16 = 5;

pub(super) const NFTA_EXTHDR_DREG: u16 = 1;
pub(super) const NFTA_EXTHDR_TYPE: u16 = 2;
pub(super) const NFTA_EXTHDR_OFFSET: u16 = 3;
pub(super) const NFTA_EXTHDR_LEN: u16 = 4;
pub(super) const NFTA_EXTHDR_FLAGS: u16 = 5;
pub(super) const NFTA_EXTHDR_OP: u16 = 6;

pub(super) const NFTA_CONNLIMIT_COUNT: u16 = 1;
pub(super) const NFTA_CONNLIMIT_FLAGS: u16 = 2;

pub(super) const NFTA_HASH_SREG: u16 = 1;
pub(super) const NFTA_HASH_DREG: u16 = 2;
pub(super) const NFTA_HASH_LEN: u16 = 3;
pub(super) const NFTA_HASH_MODULUS: u16 = 4;
pub(super) const NFTA_HASH_SEED: u16 = 5;
pub(super) const NFTA_HASH_OFFSET: u16 = 6;
pub(super) const NFTA_HASH_TYPE: u16 = 7;

pub(super) const NFTA_RT_DREG: u16 = 1;
pub(super) const NFTA_RT_KEY: u16 = 2;

pub(super) const NFTA_DYNSET_SET_NAME: u16 = 1;
pub(super) const NFTA_DYNSET_SET_ID: u16 = 2;
pub(super) const NFTA_DYNSET_OP: u16 = 3;
pub(super) const NFTA_DYNSET_SREG: u16 = 4;
pub(super) const NFTA_DYNSET_TIMEOUT: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirewallNetlinkOperation {
    EnsureBaseChains {
        queue_num: u16,
        queue_bypass: bool,
    },
    DisableBaseTable {
        table: NftTable,
    },
    ValidateInterceptionRules,
    EnsureInterceptionRule {
        chain: NftChain,
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
        rule: NftRule,
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
pub(crate) enum NetlinkFallbackReason {
    RequestTimeout,
    TransactionExecutionFailed,
    PartialUnsupportedOps,
    DroppedUnsupportedRules,
    CompatibilityValidationRequired,
}

impl fmt::Display for NetlinkFallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::RequestTimeout => "request_timeout",
            Self::TransactionExecutionFailed => "transaction_execution_failed",
            Self::PartialUnsupportedOps => "partial_unsupported_ops",
            Self::DroppedUnsupportedRules => "dropped_unsupported_rules",
            Self::CompatibilityValidationRequired => "compatibility_validation_required",
        };
        write!(f, "{value}")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NetlinkFallbackRequired {
    pub(crate) reason: NetlinkFallbackReason,
    pub(crate) detail: String,
}

impl NetlinkFallbackRequired {
    pub(crate) fn new(reason: NetlinkFallbackReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for NetlinkFallbackRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "netlink fallback required: {} ({})",
            self.reason, self.detail
        )
    }
}

impl Error for NetlinkFallbackRequired {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ParseFamily {
    Cidr,
    Connlimit,
    CtState,
    Dynset,
    Exthdr,
    Hash,
    Queue,
    Notrack,
    Reject,
    Log,
    Fib,
    Numgen,
    Limit,
    Objref,
    Quota,
    Nat,
    Lookup,
    Rt,
    Socket,
    SetOrList,
    Meta,
    IpAddrOrProto,
    Transport,
    Other,
}

impl ParseFamily {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Cidr => "cidr",
            Self::Connlimit => "connlimit",
            Self::CtState => "ct_state",
            Self::Dynset => "dynset",
            Self::Exthdr => "exthdr",
            Self::Hash => "hash",
            Self::Queue => "queue",
            Self::Notrack => "notrack",
            Self::Reject => "reject",
            Self::Log => "log",
            Self::Fib => "fib",
            Self::Numgen => "numgen",
            Self::Limit => "limit",
            Self::Objref => "objref",
            Self::Quota => "quota",
            Self::Nat => "nat",
            Self::Lookup => "lookup",
            Self::Rt => "rt",
            Self::Socket => "socket",
            Self::SetOrList => "set_or_list",
            Self::Meta => "meta",
            Self::IpAddrOrProto => "ip_addr_or_proto",
            Self::Transport => "transport",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParseFailureClass {
    EmptyExpression,
    UnsupportedShape,
    InvalidValue,
    AmbiguousForm,
    TrailingTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ParseError {
    pub(super) family: ParseFamily,
    pub(super) class: ParseFailureClass,
}

impl ParseError {
    pub(super) fn empty() -> Self {
        Self {
            family: ParseFamily::Other,
            class: ParseFailureClass::EmptyExpression,
        }
    }

    pub(super) fn unsupported_shape(family: ParseFamily) -> Self {
        Self {
            family,
            class: ParseFailureClass::UnsupportedShape,
        }
    }

    pub(super) fn invalid_value(family: ParseFamily) -> Self {
        Self {
            family,
            class: ParseFailureClass::InvalidValue,
        }
    }

    pub(super) fn trailing_tokens(family: ParseFamily) -> Self {
        Self {
            family,
            class: ParseFailureClass::TrailingTokens,
        }
    }

    pub(super) fn ambiguous_form(family: ParseFamily) -> Self {
        Self {
            family,
            class: ParseFailureClass::AmbiguousForm,
        }
    }
}

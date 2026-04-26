use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

use super::NftTable;
use super::exprs::bitwise::NftBitwise;
use super::exprs::cmp::NftCmp;
use super::exprs::connlimit::NftConnlimit;
use super::exprs::counter::NftCounter;
use super::exprs::ct::NftCt;
use super::exprs::dynset::NftDynset;
use super::exprs::exthdr::NftExthdr;
use super::exprs::fib::NftFib;
use super::exprs::hash::NftHash;
use super::exprs::immediate::NftImmediate;
use super::exprs::limit::NftLimit;
use super::exprs::log::NftLog;
use super::exprs::lookup::NftLookup;
use super::exprs::meta::NftMeta;
use super::exprs::nat::NftNat;
use super::exprs::notrack::NftNotrack;
use super::exprs::numgen::NftNumgen;
use super::exprs::payload::NftPayload;
use super::exprs::queue::NftQueue;
use super::exprs::quota::NftQuota;
use super::exprs::range::NftRange;
use super::exprs::rt::NftRt;
use super::exprs::socket::NftSocket;
use super::exprs::verdict::NftVerdict;

#[derive(Debug, Clone)]
pub(super) enum NftExpression {
    Bitwise(NftBitwise),
    Cmp(NftCmp),
    Connlimit(NftConnlimit),
    Immediate(NftImmediate),
    Lookup(NftLookup),
    Socket(NftSocket),
    Meta(NftMeta),
    Ct(NftCt),
    Dynset(NftDynset),
    Exthdr(NftExthdr),
    Payload(NftPayload),
    Fib(NftFib),
    Hash(NftHash),
    Numgen(NftNumgen),
    Limit(NftLimit),
    Log(NftLog),
    Counter(NftCounter),
    Range(NftRange),
    Rt(NftRt),
    Verdict(NftVerdict),
    Queue(NftQueue),
    Quota(NftQuota),
    Notrack(NftNotrack),
    Nat(NftNat),
}

impl NftExpression {
    pub(super) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::Bitwise(e) => e.encode(exprs),
            Self::Cmp(e) => e.encode(exprs),
            Self::Connlimit(e) => e.encode(exprs),
            Self::Immediate(e) => e.encode(exprs),
            Self::Lookup(e) => e.encode(exprs),
            Self::Socket(e) => e.encode(exprs),
            Self::Meta(e) => e.encode(exprs),
            Self::Ct(e) => e.encode(exprs),
            Self::Dynset(e) => e.encode(exprs),
            Self::Exthdr(e) => e.encode(exprs),
            Self::Payload(e) => e.encode(exprs),
            Self::Fib(e) => e.encode(exprs),
            Self::Hash(e) => e.encode(exprs),
            Self::Numgen(e) => e.encode(exprs),
            Self::Limit(e) => e.encode(exprs),
            Self::Log(e) => e.encode(exprs),
            Self::Counter(e) => e.encode(exprs),
            Self::Range(e) => e.encode(exprs),
            Self::Rt(e) => e.encode(exprs),
            Self::Verdict(e) => e.encode(exprs),
            Self::Queue(e) => e.encode(exprs),
            Self::Quota(e) => e.encode(exprs),
            Self::Notrack(e) => e.encode(exprs),
            Self::Nat(e) => e.encode(exprs),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NftRule {
    pub(super) expressions: Vec<NftExpression>,
    table: NftTable,
    chain: String,
    tag: String,
    handle: Option<u64>,
    position: Option<u64>,
    userdata: Option<Vec<u8>>,
    id: Option<u32>,
}

impl PartialEq for NftRule {
    fn eq(&self, other: &Self) -> bool {
        self.table == other.table
            && self.chain == other.chain
            && self.tag == other.tag
            && self.handle == other.handle
            && self.position == other.position
            && self.userdata == other.userdata
            && self.id == other.id
    }
}

impl Eq for NftRule {}

impl NftRule {
    pub(crate) fn new(table: NftTable, chain: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            expressions: Vec::new(),
            table,
            chain: chain.into(),
            tag: tag.into(),
            handle: None,
            position: None,
            userdata: None,
            id: None,
        }
    }

    pub(super) fn from_expressions(expressions: Vec<NftExpression>) -> Self {
        Self {
            expressions,
            table: NftTable::new("", ""),
            chain: String::new(),
            tag: String::new(),
            handle: None,
            position: None,
            userdata: None,
            id: None,
        }
    }

    pub(crate) fn with_target(mut self, table: NftTable, chain: impl Into<String>) -> Self {
        self.table = table;
        self.chain = chain.into();
        self
    }

    pub(crate) fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = tag.into();
        self
    }

    pub(crate) fn with_handle(mut self, handle: u64) -> Self {
        self.handle = Some(handle);
        self
    }

    pub(crate) fn with_position(mut self, position: u64) -> Self {
        self.position = Some(position);
        self
    }

    pub(crate) fn with_userdata(mut self, userdata: Vec<u8>) -> Self {
        self.userdata = Some(userdata);
        self
    }

    pub(crate) fn with_id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    pub(crate) fn table(&self) -> &NftTable {
        &self.table
    }

    pub(crate) fn chain(&self) -> &str {
        &self.chain
    }

    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn expression_count(&self) -> usize {
        self.expressions.len()
    }

    pub(crate) fn handle(&self) -> Option<u64> {
        self.handle
    }

    pub(crate) fn position(&self) -> Option<u64> {
        self.position
    }

    pub(crate) fn userdata(&self) -> Option<&[u8]> {
        self.userdata.as_deref()
    }

    pub(crate) fn id(&self) -> Option<u32> {
        self.id
    }

    pub(crate) fn encoded_userdata(&self) -> &[u8] {
        self.userdata
            .as_deref()
            .unwrap_or_else(|| self.tag.as_bytes())
    }
}

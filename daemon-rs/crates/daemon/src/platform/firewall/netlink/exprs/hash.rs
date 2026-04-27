use crate::platform::netlink::attrs::{
    NetlinkAttributeBuffer, NetlinkAttributeRecord, finalize_nested_attr, push_attr_header,
    push_nested_attr_header,
};
use netlink_bindings::nftables;

use super::super::{
    NFTA_EXPR_DATA, NFTA_HASH_DREG, NFTA_HASH_LEN, NFTA_HASH_MODULUS, NFTA_HASH_OFFSET,
    NFTA_HASH_SEED, NFTA_HASH_SREG, NFTA_HASH_TYPE,
};
use super::NftExpression;
use super::shared::{
    OptionParseStep, parse_cmp_mapped_conditions, parse_unsigned_token, push_cmp_from_reg1,
    push_payload_load_to_reg1, scan_option_sequence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) enum HashType {
    Jenkins = 0,
    Sym = 1,
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftHash {
    pub(super) hash_type: HashType,
    pub(super) sreg: Option<nftables::Registers>,
    pub(super) dreg: nftables::Registers,
    pub(super) len: u32,
    pub(super) modulus: u32,
    pub(super) seed: u32,
    pub(super) offset: u32,
    pub(super) op: nftables::CmpOps,
    pub(super) value: u32,
    pub(super) payload_base: Option<u32>,
    pub(super) payload_offset: Option<u32>,
}

struct PayloadSpec {
    base: u32,
    offset: u32,
    len: u32,
}

fn parse_jhash_payload(tokens: &[&str], i: usize, end: usize) -> Option<(PayloadSpec, usize)> {
    if i + 1 >= end {
        return None;
    }

    let (base, addr_offset, len) = match (tokens.get(i)?, tokens.get(i + 1)?) {
        (&"ip", &"saddr") => (nftables::PayloadBase::NetworkHeader as u32, 12_u32, 4_u32),
        (&"ip", &"daddr") => (nftables::PayloadBase::NetworkHeader as u32, 16_u32, 4_u32),
        (&"ip6", &"saddr") => (nftables::PayloadBase::NetworkHeader as u32, 8_u32, 16_u32),
        (&"ip6", &"daddr") => (nftables::PayloadBase::NetworkHeader as u32, 24_u32, 16_u32),
        _ => return None,
    };

    Some((
        PayloadSpec {
            base,
            offset: addr_offset,
            len,
        },
        i + 2,
    ))
}

pub(crate) fn parse_hash_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    match tokens.get(i)? {
        &"jhash" => parse_jhash_conditions(tokens, i, end, expansions),
        &"symhash" => parse_symhash_conditions(tokens, i, end, expansions),
        _ => None,
    }
}

fn parse_jhash_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    let (payload, next) = parse_jhash_payload(tokens, i + 1, end)?;

    if tokens.get(next) != Some(&"mod") {
        return None;
    }

    let modulus = parse_unsigned_token::<u32>(*tokens.get(next + 1)?)?;
    if modulus == 0 {
        return None;
    }

    let mut seed = 0_u32;
    let mut offset = 0_u32;
    let mut cmp_start = next + 2;

    cmp_start = scan_option_sequence(tokens, cmp_start, end, |tokens, index, end| {
        match tokens[index] {
            "seed" if index + 1 < end => match parse_unsigned_token::<u32>(tokens[index + 1]) {
                Some(s) => {
                    seed = s;
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            },
            "offset" if index + 1 < end => match parse_unsigned_token::<u32>(tokens[index + 1]) {
                Some(o) => {
                    offset = o;
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            },
            _ => OptionParseStep::Stop,
        }
    })?;

    parse_cmp_mapped_conditions(
        tokens,
        cmp_start,
        end,
        expansions,
        parse_unsigned_token::<u32>,
        |op, value| {
            NftExpression::Hash(NftHash {
                hash_type: HashType::Jenkins,
                sreg: Some(nftables::Registers::Reg1),
                dreg: nftables::Registers::Reg1,
                len: payload.len,
                modulus,
                seed,
                offset,
                op,
                value,
                payload_base: Some(payload.base),
                payload_offset: Some(payload.offset),
            })
        },
    )
}

fn parse_symhash_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i + 1) != Some(&"mod") {
        return None;
    }

    let modulus = parse_unsigned_token::<u32>(*tokens.get(i + 2)?)?;
    if modulus == 0 {
        return None;
    }

    let mut offset = 0_u32;
    let mut cmp_start = i + 3;

    if tokens.get(cmp_start) == Some(&"offset") {
        offset = parse_unsigned_token::<u32>(*tokens.get(cmp_start + 1)?)?;
        cmp_start += 2;
    }

    parse_cmp_mapped_conditions(
        tokens,
        cmp_start,
        end,
        expansions,
        parse_unsigned_token::<u32>,
        |op, value| {
            NftExpression::Hash(NftHash {
                hash_type: HashType::Sym,
                sreg: None,
                dreg: nftables::Registers::Reg1,
                len: 0,
                modulus,
                seed: 0,
                offset,
                op,
                value,
                payload_base: None,
                payload_offset: None,
            })
        },
    )
}

impl NftHash {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        // For jhash: load payload to Reg1 first
        let exprs = if let (Some(base), Some(p_offset)) = (self.payload_base, self.payload_offset) {
            push_payload_load_to_reg1(exprs, base, p_offset, self.len)
        } else {
            exprs
        };

        let mut expr = exprs.nested_elem().push_name_bytes(b"hash");
        let data_offset = push_nested_attr_header(expr.attrs_mut(), NFTA_EXPR_DATA);

        if let Some(sreg) = self.sreg {
            push_attr_header(expr.attrs_mut(), NFTA_HASH_SREG, 4);
            expr.attrs_mut().extend((sreg as u32).to_be_bytes());
        }

        push_attr_header(expr.attrs_mut(), NFTA_HASH_DREG, 4);
        expr.attrs_mut().extend((self.dreg as u32).to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_HASH_LEN, 4);
        expr.attrs_mut().extend(self.len.to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_HASH_MODULUS, 4);
        expr.attrs_mut().extend(self.modulus.to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_HASH_SEED, 4);
        expr.attrs_mut().extend(self.seed.to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_HASH_OFFSET, 4);
        expr.attrs_mut().extend(self.offset.to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_HASH_TYPE, 4);
        expr.attrs_mut()
            .extend((self.hash_type as u32).to_be_bytes());

        finalize_nested_attr(expr.attrs_mut(), data_offset);
        let exprs = expr.end_nested();

        push_cmp_from_reg1(exprs, self.op, &self.value.to_be_bytes())
    }
}

use netlink_bindings::nftables;
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};

use super::super::NFTA_EXPR_DATA;
use super::NftExpression;
use super::cmp::NftCmp;
use super::shared::{
    parse_cmp_and_value_index, parse_named_value, parse_unsigned_token, parse_value_list,
};

const NFTA_SOCKET_KEY: u16 = 1;
const NFTA_SOCKET_DREG: u16 = 2;
const NFTA_SOCKET_LEVEL: u16 = 3;

/// Socket key for matching on existing socket attributes.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub(in crate::platform::firewall::netlink) enum NftSocketKey {
    Transparent = 0,
    Mark = 1,
    Wildcard = 2,
    CgroupV2 = 3,
}

const SOCKET_KEY_NAMES: &[(&str, NftSocketKey)] = &[
    ("transparent", NftSocketKey::Transparent),
    ("mark", NftSocketKey::Mark),
    ("wildcard", NftSocketKey::Wildcard),
    ("cgroupv2", NftSocketKey::CgroupV2),
];

pub(crate) fn parse_socket_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"socket") {
        return None;
    }

    let key = parse_socket_key(*tokens.get(i + 1)?)?;
    let (level, cmp_start) = parse_socket_level(tokens, i + 2, end, key)?;
    let (op, value_idx) = parse_cmp_and_value_index(tokens, cmp_start, end)?;
    let (values, next) = parse_value_list(tokens, value_idx, end)?;

    let mut next_expansions = Vec::new();
    for value in values {
        let data = parse_socket_cmp_data(key, value)?;
        for current in &expansions {
            let mut updated = current.clone();
            updated.push(NftExpression::Socket(NftSocket {
                key,
                dreg: nftables::Registers::Reg1,
                level,
            }));
            updated.push(NftExpression::Cmp(NftCmp {
                sreg: nftables::Registers::Reg1,
                op,
                data: data.clone(),
            }));
            next_expansions.push(updated);
        }
    }

    Some((next_expansions, next))
}

fn parse_socket_key(token: &str) -> Option<NftSocketKey> {
    parse_named_value(token, SOCKET_KEY_NAMES, |value| {
        parse_unsigned_token::<u32>(value).and_then(socket_key_from_raw)
    })
}

fn socket_key_from_raw(raw: u32) -> Option<NftSocketKey> {
    Some(match raw {
        0 => NftSocketKey::Transparent,
        1 => NftSocketKey::Mark,
        2 => NftSocketKey::Wildcard,
        3 => NftSocketKey::CgroupV2,
        _ => return None,
    })
}

fn parse_socket_level(
    tokens: &[&str],
    start: usize,
    end: usize,
    key: NftSocketKey,
) -> Option<(u32, usize)> {
    if matches!(key, NftSocketKey::CgroupV2) && tokens.get(start) == Some(&"level") {
        let level = parse_unsigned_token::<u32>(*tokens.get(start + 1)?)?;
        return Some((level, start + 2));
    }

    if start > end {
        return None;
    }

    Some((0, start))
}

fn parse_socket_cmp_data(key: NftSocketKey, token: &str) -> Option<Vec<u8>> {
    match key {
        NftSocketKey::Transparent | NftSocketKey::Wildcard => {
            Some(parse_socket_bool_or_u32(token)?.to_be_bytes().to_vec())
        }
        NftSocketKey::Mark => Some(parse_unsigned_token::<u32>(token)?.to_be_bytes().to_vec()),
        NftSocketKey::CgroupV2 => Some(parse_unsigned_token::<u64>(token)?.to_be_bytes().to_vec()),
    }
}

fn parse_socket_bool_or_u32(token: &str) -> Option<u32> {
    match token {
        "true" => Some(1),
        "false" => Some(0),
        _ => parse_unsigned_token::<u32>(token),
    }
}

/// Standalone socket expression.
///
/// Matches on existing UDP/TCP sockets and their attributes,
/// storing the result into the destination register.
#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftSocket {
    pub(super) key: NftSocketKey,
    pub(super) dreg: nftables::Registers,
    pub(super) level: u32,
}

impl NftSocket {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let mut expr = exprs.nested_elem().push_name_bytes(b"socket");
        let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

        push_header(expr.as_rec_mut(), NFTA_SOCKET_KEY, 4);
        expr.as_rec_mut().extend((self.key as u32).to_be_bytes());

        push_header(expr.as_rec_mut(), NFTA_SOCKET_DREG, 4);
        expr.as_rec_mut().extend((self.dreg as u32).to_be_bytes());

        push_header(expr.as_rec_mut(), NFTA_SOCKET_LEVEL, 4);
        expr.as_rec_mut().extend(self.level.to_be_bytes());

        finalize_nested_header(expr.as_rec_mut(), data_offset);
        expr.end_nested()
    }
}

use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionParseStep {
    Consumed(usize),
    Stop,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedCmp {
    pub(crate) op: nftables::CmpOps,
    pub(crate) value_idx: usize,
}

pub(crate) fn parse_cmp_and_value_index(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(nftables::CmpOps, usize)> {
    let parsed = parse_cmp(tokens, start, end)?;
    Some((parsed.op, parsed.value_idx))
}

pub(crate) fn parse_cmp(tokens: &[&str], start: usize, end: usize) -> Option<ParsedCmp> {
    if start >= end {
        return None;
    }

    match tokens[start] {
        "==" if start + 1 < end => Some(ParsedCmp {
            op: nftables::CmpOps::Eq,
            value_idx: start + 1,
        }),
        "!=" if start + 1 < end => Some(ParsedCmp {
            op: nftables::CmpOps::Neq,
            value_idx: start + 1,
        }),
        "<" if start + 1 < end => Some(ParsedCmp {
            op: nftables::CmpOps::Lt,
            value_idx: start + 1,
        }),
        "<=" if start + 1 < end => Some(ParsedCmp {
            op: nftables::CmpOps::Lte,
            value_idx: start + 1,
        }),
        ">" if start + 1 < end => Some(ParsedCmp {
            op: nftables::CmpOps::Gt,
            value_idx: start + 1,
        }),
        ">=" if start + 1 < end => Some(ParsedCmp {
            op: nftables::CmpOps::Gte,
            value_idx: start + 1,
        }),
        "==" | "!=" | "<" | "<=" | ">" | ">=" => None,
        _ => Some(ParsedCmp {
            op: nftables::CmpOps::Eq,
            value_idx: start,
        }),
    }
}

pub(crate) fn parse_cmp_values<'a>(
    tokens: &'a [&'a str],
    start: usize,
    end: usize,
) -> Option<(nftables::CmpOps, Vec<&'a str>, usize)> {
    let parsed = parse_cmp(tokens, start, end)?;
    let (values, next) = parse_value_list(tokens, parsed.value_idx, end)?;
    Some((parsed.op, values, next))
}

pub(crate) fn push_condition<C: Clone>(expansions: &mut Vec<Vec<C>>, condition: C) {
    for current in expansions.iter_mut() {
        current.push(condition.clone());
    }
}

pub(crate) fn parse_and_expand_conditions<'a, C, F>(
    tokens: &'a [&'a str],
    value_idx: usize,
    end: usize,
    expansions: Vec<Vec<C>>,
    mut parse_condition: F,
) -> Option<(Vec<Vec<C>>, usize)>
where
    C: Clone,
    F: FnMut(&'a str) -> Option<C>,
{
    let (values, next) = parse_value_list(tokens, value_idx, end)?;
    let expanded = expand_conditions(expansions, values, |value| parse_condition(value))?;
    Some((expanded, next))
}

pub(crate) fn parse_cmp_mapped_conditions<'a, T, C, P, B>(
    tokens: &'a [&'a str],
    cmp_start: usize,
    end: usize,
    expansions: Vec<Vec<C>>,
    mut parse_value: P,
    mut build: B,
) -> Option<(Vec<Vec<C>>, usize)>
where
    T: Clone,
    C: Clone,
    P: FnMut(&'a str) -> Option<T>,
    B: FnMut(nftables::CmpOps, T) -> C,
{
    let (op, value_idx) = parse_cmp_and_value_index(tokens, cmp_start, end)?;
    parse_and_expand_conditions(tokens, value_idx, end, expansions, |value| {
        Some(build(op, parse_value(value)?))
    })
}

pub(crate) fn parse_cmp_mapped_conditions_with_guard<'a, T, C, P, B, G>(
    tokens: &'a [&'a str],
    cmp_start: usize,
    end: usize,
    expansions: Vec<Vec<C>>,
    mut is_allowed_op: G,
    mut parse_value: P,
    mut build: B,
) -> Option<(Vec<Vec<C>>, usize)>
where
    T: Clone,
    C: Clone,
    P: FnMut(&'a str) -> Option<T>,
    B: FnMut(nftables::CmpOps, T) -> C,
    G: FnMut(nftables::CmpOps) -> bool,
{
    let (op, value_idx) = parse_cmp_and_value_index(tokens, cmp_start, end)?;
    if !is_allowed_op(op) {
        return None;
    }

    parse_and_expand_conditions(tokens, value_idx, end, expansions, |value| {
        Some(build(op, parse_value(value)?))
    })
}

pub(crate) fn parse_eq_neq_mapped_string_conditions<'a, C, P, B>(
    tokens: &'a [&'a str],
    cmp_start: usize,
    end: usize,
    expansions: Vec<Vec<C>>,
    parse_value: P,
    mut build: B,
) -> Option<(Vec<Vec<C>>, usize)>
where
    C: Clone,
    P: FnMut(&'a str) -> Option<&'a str>,
    B: FnMut(nftables::CmpOps, String) -> C,
{
    parse_cmp_mapped_conditions_with_guard(
        tokens,
        cmp_start,
        end,
        expansions,
        |op| matches!(op, nftables::CmpOps::Eq | nftables::CmpOps::Neq),
        parse_value,
        |op, value| build(op, value.to_string()),
    )
}

pub(crate) fn parse_eq_mask_condition<'a, C, M, B>(
    tokens: &'a [&'a str],
    cmp_start: usize,
    end: usize,
    expansions: &mut Vec<Vec<C>>,
    mut map_value: M,
    mut build: B,
) -> Option<usize>
where
    C: Clone,
    M: FnMut(&'a str) -> Option<u32>,
    B: FnMut(u32) -> C,
{
    let (op, value_idx) = parse_cmp_and_value_index(tokens, cmp_start, end)?;
    if !matches!(op, nftables::CmpOps::Eq) {
        return None;
    }

    let (values, next) = parse_value_list(tokens, value_idx, end)?;
    let mut mask = 0_u32;
    for value in values {
        mask |= map_value(value)?;
    }
    if mask == 0 {
        return None;
    }

    push_condition(expansions, build(mask));
    Some(next)
}

pub(crate) fn expand_conditions<'a, C, F>(
    expansions: Vec<Vec<C>>,
    values: Vec<&'a str>,
    mut parse_condition: F,
) -> Option<Vec<Vec<C>>>
where
    C: Clone,
    F: FnMut(&'a str) -> Option<C>,
{
    let mut next_expansions = Vec::new();
    for value in values {
        let condition = parse_condition(value)?;
        for current in &expansions {
            let mut updated = current.clone();
            updated.push(condition.clone());
            next_expansions.push(updated);
        }
    }
    Some(next_expansions)
}

pub(crate) fn is_lookup_set_token(token: &str) -> bool {
    token.starts_with('@')
}

pub(crate) fn parse_lookup_set_name(token: &str) -> Option<&str> {
    let set = token.strip_prefix('@')?;
    if set.is_empty() {
        return None;
    }
    Some(set)
}

pub(crate) fn parse_lookup_set_cmp(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(bool, usize, usize)> {
    match tokens.get(start) {
        Some(token) if is_lookup_set_token(token) => Some((false, start, start + 1)),
        Some(&"==") if start + 1 < end && is_lookup_set_token(tokens[start + 1]) => {
            Some((false, start + 1, start + 2))
        }
        Some(&"!=") if start + 1 < end && is_lookup_set_token(tokens[start + 1]) => {
            Some((true, start + 1, start + 2))
        }
        _ => None,
    }
}

pub(crate) fn parse_selector_offset(
    token: &str,
    first: (&str, u32),
    second: (&str, u32),
) -> Option<u32> {
    if token == first.0 {
        return Some(first.1);
    }

    if token == second.0 {
        return Some(second.1);
    }

    None
}

pub(crate) fn parse_value_list<'a>(
    tokens: &'a [&'a str],
    start: usize,
    end: usize,
) -> Option<(Vec<&'a str>, usize)> {
    if start >= end {
        return None;
    }

    if !tokens[start].starts_with('{') {
        return Some((
            split_csv_values(trim_trailing_comma(tokens[start])),
            start + 1,
        ));
    }

    let mut values = Vec::new();
    let mut index = start;
    let mut first = true;
    while index < end {
        let mut token = tokens[index];
        if first {
            first = false;
            token = token.strip_prefix('{').unwrap_or(token);
            if token.is_empty() {
                index += 1;
                continue;
            }
        }

        let mut reached_end = false;
        if let Some(stripped) = token.strip_suffix('}') {
            token = stripped;
            reached_end = true;
        }

        let token = trim_trailing_comma(token);
        values.extend(split_csv_values(token));

        if reached_end {
            return Some((values, index + 1));
        }

        index += 1;
    }

    None
}

pub(crate) fn scan_option_sequence<F>(
    tokens: &[&str],
    start: usize,
    end: usize,
    mut parse_option: F,
) -> Option<usize>
where
    F: FnMut(&[&str], usize, usize) -> OptionParseStep,
{
    let mut index = start;
    while index < end {
        match parse_option(tokens, index, end) {
            OptionParseStep::Consumed(next) => index = next,
            OptionParseStep::Stop => break,
            OptionParseStep::Invalid => return None,
        }
    }

    Some(index)
}

pub(crate) fn scan_comment_tail(tokens: &[&str], start: usize, end: usize) -> Option<usize> {
    scan_option_sequence(tokens, start, end, |tokens, index, _end| {
        match tokens[index] {
            "comment" => OptionParseStep::Stop,
            _ => OptionParseStep::Invalid,
        }
    })
}

pub(crate) fn split_csv_values(token: &str) -> Vec<&str> {
    token
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect()
}

pub(crate) fn trim_trailing_comma(token: &str) -> &str {
    token.trim_end_matches(',')
}

pub(crate) fn parse_token<T>(token: &str) -> Option<T>
where
    T: FromStr,
{
    token.parse::<T>().ok()
}

fn parse_decimal_token<T>(token: &str) -> Option<T>
where
    T: FromStr,
{
    parse_token::<T>(token)
}

pub(crate) fn parse_decimal_range_token<T>(token: &str) -> Option<(T, T)>
where
    T: FromStr,
{
    let (start, end) = token.split_once('-')?;
    Some((parse_decimal_token(start)?, parse_decimal_token(end)?))
}

pub(crate) fn parse_named_value<T, F>(token: &str, names: &[(&str, T)], fallback: F) -> Option<T>
where
    T: Copy,
    F: FnOnce(&str) -> Option<T>,
{
    names
        .iter()
        .find(|(name, _)| *name == token)
        .map(|(_, value)| *value)
        .or_else(|| fallback(token))
}

pub(crate) fn parse_proto(token: &str) -> Option<u8> {
    match token {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        _ => parse_token::<u8>(token),
    }
}

pub(crate) fn parse_nfproto(token: &str) -> Option<u8> {
    Some(match token {
        "inet" => 1,
        "ipv4" => 2,
        "arp" => 3,
        "bridge" => 7,
        "ipv6" => 10,
        _ => parse_token::<u8>(token)?,
    })
}

pub(crate) fn parse_unsigned_token<T>(token: &str) -> Option<T>
where
    T: TryFrom<u64>,
{
    let raw = if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        parse_decimal_token::<u64>(token)?
    };

    T::try_from(raw).ok()
}

pub(crate) fn parse_single_or_range_token<T>(token: &str) -> Option<(T, T)>
where
    T: FromStr + Copy + PartialOrd,
{
    if let Some((start, end)) = parse_decimal_range_token::<T>(token) {
        if start > end {
            return None;
        }
        return Some((start, end));
    }

    let value = parse_decimal_token::<T>(token)?;
    Some((value, value))
}

pub(crate) fn parse_nonempty_single_or_range_token<T>(token: &str) -> Option<(T, T)>
where
    T: FromStr + Copy + PartialOrd,
{
    if token.is_empty() {
        return None;
    }

    parse_single_or_range_token::<T>(token)
}

pub(crate) fn parse_colon_prefixed_nonempty_single_or_range_token<T>(token: &str) -> Option<(T, T)>
where
    T: FromStr + Copy + PartialOrd,
{
    let spec = token.strip_prefix(':')?;
    parse_nonempty_single_or_range_token::<T>(spec)
}

pub(crate) fn parse_nonempty_single_token_without_range<T>(token: &str) -> Option<T>
where
    T: FromStr,
{
    if token.is_empty() || token.contains('-') {
        return None;
    }

    parse_decimal_token::<T>(token)
}

pub(crate) fn normalize_optional_range_pair<T>(range: Option<(T, T)>) -> (Option<T>, Option<T>)
where
    T: Copy,
{
    match range {
        Some((min, max)) => (Some(min), Some(max)),
        None => (None, None),
    }
}

pub(crate) fn parse_ip_optional_port_spec_token<'a>(
    token: &'a str,
) -> Option<(IpAddr, Option<&'a str>)> {
    if let Some(v6_rest) = token.strip_prefix('[') {
        let bracket_end = v6_rest.find(']')?;
        let host = &v6_rest[..bracket_end];
        let addr = parse_token::<IpAddr>(host)?;
        if !matches!(addr, IpAddr::V6(_)) {
            return None;
        }

        let rest = &v6_rest[bracket_end + 1..];
        if rest.is_empty() {
            return Some((addr, None));
        }

        let port_spec = rest.strip_prefix(':')?;
        if port_spec.is_empty() {
            return None;
        }

        return Some((addr, Some(port_spec)));
    }

    if let Some(addr) = parse_token::<IpAddr>(token) {
        return Some((addr, None));
    }

    if let Some((host, port_spec)) = token.split_once(':') {
        let addr = parse_token::<Ipv4Addr>(host)?;
        if port_spec.is_empty() {
            return None;
        }
        return Some((IpAddr::V4(addr), Some(port_spec)));
    }

    None
}

pub(crate) fn parse_optional_ip_required_port_spec_token<'a>(
    token: &'a str,
) -> Option<(Option<IpAddr>, &'a str)> {
    if let Some(port_spec) = token.strip_prefix(':') {
        if port_spec.is_empty() {
            return None;
        }
        return Some((None, port_spec));
    }

    let (addr, port_spec) = parse_ip_optional_port_spec_token(token)?;
    Some((Some(addr), port_spec?))
}

pub(crate) fn parse_named_bitmask_value<T>(token: &str, names: &[(&str, T)]) -> Option<T>
where
    T: TryFrom<u64> + Copy + Default + PartialEq + std::ops::BitOrAssign,
{
    if let Some(value) = parse_unsigned_token::<T>(token) {
        return Some(value);
    }

    let mut value = T::default();
    for item in token
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        value |= names
            .iter()
            .find(|(name, _)| *name == item)
            .map(|(_, flag)| *flag)?;
    }

    if value == T::default() {
        return None;
    }

    Some(value)
}

pub(crate) fn parse_ascii_symbol_token<'a>(
    token: &'a str,
    max_len: usize,
    extra_chars: &[char],
) -> Option<&'a str> {
    parse_ascii_symbol_token_impl(token, max_len, extra_chars, false)
}

pub(crate) fn parse_quoted_ascii_symbol_token<'a>(
    token: &'a str,
    max_len: usize,
    extra_chars: &[char],
) -> Option<&'a str> {
    parse_ascii_symbol_token_impl(token, max_len, extra_chars, true)
}

fn parse_ascii_symbol_token_impl<'a>(
    token: &'a str,
    max_len: usize,
    extra_chars: &[char],
    trim_quotes: bool,
) -> Option<&'a str> {
    let token = if trim_quotes {
        token.trim_matches('"')
    } else {
        token
    };

    if token.is_empty() || token.len() > max_len {
        return None;
    }

    if token
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || extra_chars.contains(&c)))
    {
        return None;
    }

    Some(token)
}

pub(crate) fn parse_ifname(token: &str) -> Option<&str> {
    if token.is_empty() || token.len() > 15 {
        return None;
    }

    if token
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@' | '+')))
    {
        return None;
    }

    Some(token)
}

pub(crate) fn parse_kind_token(token: &str) -> Option<&str> {
    if token.is_empty() || token.len() > 32 {
        return None;
    }

    if token
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        return None;
    }

    Some(token)
}

pub(crate) fn parse_ip_range(token: &str) -> Option<(IpAddr, IpAddr)> {
    let (start, end) = token.split_once('-')?;
    let start = parse_token::<IpAddr>(start)?;
    let end = parse_token::<IpAddr>(end)?;
    if std::mem::discriminant(&start) != std::mem::discriminant(&end) {
        return None;
    }
    Some((start, end))
}

pub(crate) fn parse_ip_cidr(token: &str) -> Option<(IpAddr, u128)> {
    let (addr_part, prefix_part) = token.split_once('/')?;
    let addr = parse_token::<IpAddr>(addr_part)?;
    let prefix = parse_token::<u8>(prefix_part)?;

    match addr {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }

            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = Ipv4Addr::from(u32::from(v4) & mask);
            Some((IpAddr::V4(network), u128::from(mask)))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }

            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = Ipv6Addr::from(u128::from_be_bytes(v6.octets()) & mask);
            Some((IpAddr::V6(network), mask))
        }
    }
}

pub(crate) fn cmp_to_range_op(op: nftables::CmpOps) -> Option<nftables::RangeOps> {
    match op {
        nftables::CmpOps::Eq => Some(nftables::RangeOps::Eq),
        nftables::CmpOps::Neq => Some(nftables::RangeOps::Neq),
        _ => None,
    }
}

pub(crate) fn push_cmp_from_reg1<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    op: nftables::CmpOps,
    value: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    exprs
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(nftables::Registers::Reg1 as u32)
        .push_op(op as u32)
        .nested_data()
        .push_value(value)
        .end_nested()
        .end_nested()
        .end_nested()
}

pub(crate) fn push_cmp_after_load_to_reg1<Prev: Rec, F>(
    exprs: nftables::PushExprListAttrs<Prev>,
    op: nftables::CmpOps,
    value: &[u8],
    load_to_reg1: F,
) -> nftables::PushExprListAttrs<Prev>
where
    F: FnOnce(nftables::PushExprListAttrs<Prev>) -> nftables::PushExprListAttrs<Prev>,
{
    push_cmp_from_reg1(load_to_reg1(exprs), op, value)
}

pub(crate) fn push_meta_cmp_from_key<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    key: nftables::MetaKeys,
    op: nftables::CmpOps,
    value: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    push_cmp_after_load_to_reg1(exprs, op, value, |exprs| {
        exprs
            .nested_elem()
            .nested_data_meta()
            .push_key(key as u32)
            .push_dreg(nftables::Registers::Reg1 as u32)
            .end_nested()
            .end_nested()
    })
}

pub(crate) fn push_ct_cmp_from_key<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    key: nftables::CtKeys,
    op: nftables::CmpOps,
    value: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    push_cmp_after_load_to_reg1(exprs, op, value, |exprs| {
        exprs
            .nested_elem()
            .nested_data_ct()
            .push_dreg(nftables::Registers::Reg1 as u32)
            .push_key(key as u32)
            .end_nested()
            .end_nested()
    })
}

pub(crate) fn push_fib_cmp_from_result<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    result: u32,
    flags: u32,
    op: nftables::CmpOps,
    value: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    push_cmp_after_load_to_reg1(exprs, op, value, |exprs| {
        exprs
            .nested_elem()
            .nested_data_fib()
            .push_dreg(nftables::Registers::Reg1 as u32)
            .push_result(result)
            .push_flags(flags)
            .end_nested()
            .end_nested()
    })
}

pub(crate) fn push_range_from_reg1<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    op: nftables::RangeOps,
    start: &[u8],
    end: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    exprs
        .nested_elem()
        .nested_data_range()
        .push_sreg(nftables::Registers::Reg1 as u32)
        .push_op(op as u32)
        .nested_from_data()
        .push_value(start)
        .end_nested()
        .nested_to_data()
        .push_value(end)
        .end_nested()
        .end_nested()
        .end_nested()
}

pub(crate) fn push_payload_load_to_reg1<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    base: u32,
    offset: u32,
    len: u32,
) -> nftables::PushExprListAttrs<Prev> {
    exprs
        .nested_elem()
        .nested_data_payload()
        .push_dreg(nftables::Registers::Reg1 as u32)
        .push_base(base)
        .push_offset(offset)
        .push_len(len)
        .end_nested()
        .end_nested()
}

pub(crate) fn push_lookup_from_reg1<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    set: &str,
    invert: bool,
    dreg: Option<u32>,
) -> nftables::PushExprListAttrs<Prev> {
    let lookup_flags = if invert {
        nftables::LookupFlags::Invert as u32
    } else {
        0
    };

    let mut lookup = exprs
        .nested_elem()
        .nested_data_lookup()
        .push_set_bytes(set.as_bytes())
        .push_sreg(nftables::Registers::Reg1 as u32)
        .push_flags(lookup_flags);

    if let Some(dreg) = dreg {
        lookup = lookup.push_dreg(dreg);
    }

    lookup.end_nested().end_nested()
}

pub(crate) fn push_payload_range<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    base: u32,
    offset: u32,
    len: u32,
    op: nftables::RangeOps,
    start: &[u8],
    end: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    push_range_from_reg1(
        push_payload_load_to_reg1(exprs, base, offset, len),
        op,
        start,
        end,
    )
}

pub(crate) fn push_payload_cmp<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    base: u32,
    offset: u32,
    len: u32,
    op: nftables::CmpOps,
    value: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    push_cmp_after_load_to_reg1(exprs, op, value, |exprs| {
        push_payload_load_to_reg1(exprs, base, offset, len)
    })
}

pub(crate) fn push_numgen_cmp<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    gen_type: u32,
    modulus: u32,
    offset: u32,
    op: nftables::CmpOps,
    value: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    let exprs = exprs
        .nested_elem()
        .nested_data_numgen()
        .push_dreg(nftables::Registers::Reg1 as u32)
        .push_modulus(modulus)
        .push_type(gen_type)
        .push_offset(offset)
        .end_nested()
        .end_nested();
    push_cmp_from_reg1(exprs, op, value)
}

pub(crate) fn parse_icmp_type(is_v6: bool, token: &str) -> Option<u8> {
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

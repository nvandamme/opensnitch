use netlink_bindings::nftables;

use super::super::NftExpression;
use super::super::shared::{
    cmp_to_range_op, expand_conditions, is_lookup_set_token, parse_cmp_mapped_conditions,
    parse_cmp_values, parse_decimal_range_token, parse_lookup_set_cmp, parse_lookup_set_name,
    parse_selector_offset, parse_token, parse_unsigned_token, push_condition,
};
use super::super::verdict::NftVerdict;
use super::{NftPayload, PayloadParseResult};

pub(super) fn parse_th_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<PayloadParseResult> {
    parse_th_like_conditions(tokens, i, end, expansions)
}

pub(super) fn parse_th_like_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<PayloadParseResult> {
    if tokens.get(i) == Some(&"udp") && matches!(tokens.get(i + 1), Some(&"length") | Some(&"len"))
    {
        return parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, length| NftExpression::Payload(NftPayload::UdpLength { op, length }),
        );
    }

    if tokens.get(i + 2) == Some(&"vmap")
        && tokens.get(i + 3).is_some_and(|t| is_lookup_set_token(t))
    {
        let offset = parse_selector_offset(*tokens.get(i + 1)?, ("sport", 0), ("dport", 2))?;
        let set = parse_lookup_set_name(*tokens.get(i + 3)?)?;
        let mut ex = expansions;
        push_condition(
            &mut ex,
            NftExpression::Verdict(NftVerdict::VmapLookup {
                payload_base: nftables::PayloadBase::TransportHeader,
                offset,
                len: 2,
                set: set.to_string(),
            }),
        );
        return Some((ex, i + 4));
    }

    if let Some((invert, set_idx, next)) = parse_lookup_set_cmp(tokens, i + 2, end) {
        let offset = parse_selector_offset(*tokens.get(i + 1)?, ("sport", 0), ("dport", 2))?;
        let set = parse_lookup_set_name(*tokens.get(set_idx)?)?;
        let mut ex = expansions;
        push_condition(
            &mut ex,
            NftExpression::Payload(NftPayload::LookupTransportPort {
                offset,
                set: set.to_string(),
                invert,
            }),
        );
        return Some((ex, next));
    }

    let (op, values, next) = parse_cmp_values(tokens, i + 2, end)?;
    let offset = parse_selector_offset(*tokens.get(i + 1)?, ("sport", 0), ("dport", 2))?;
    let next_expansions = expand_conditions(expansions, values, |value| {
        let condition = if let Some((start, end_port)) = parse_decimal_range_token::<u16>(value) {
            let range_op = cmp_to_range_op(op)?;
            NftExpression::Payload(NftPayload::TransportPortRange {
                op: range_op,
                offset,
                start,
                end: end_port,
            })
        } else {
            let port = parse_token::<u16>(value)?;
            NftExpression::Payload(NftPayload::TransportPort { op, offset, port })
        };

        Some(condition)
    })?;
    Some((next_expansions, next))
}

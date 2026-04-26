use netlink_bindings::nftables;

use super::super::NftExpression;
use super::super::shared::{
    cmp_to_range_op, expand_conditions, is_lookup_set_token, parse_cmp_mapped_conditions,
    parse_cmp_values, parse_ip_cidr, parse_ip_range, parse_lookup_set_cmp, parse_lookup_set_name,
    parse_proto, parse_selector_offset, parse_token, parse_unsigned_token, push_condition,
};
use super::super::verdict::NftVerdict;
use super::{NftPayload, PayloadParseResult};

pub(super) fn parse_ip_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<PayloadParseResult> {
    if tokens.get(i + 1) == Some(&"protocol") {
        let (next_expansions, next) = parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_proto,
            |op, proto| NftExpression::Payload(NftPayload::IpProtocol { op, proto }),
        )?;
        return Some((next_expansions, next));
    }

    if tokens.get(i + 1) == Some(&"ttl") {
        let (next_expansions, next) = parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u8>,
            |op, ttl| NftExpression::Payload(NftPayload::IpTtl { op, ttl }),
        )?;
        return Some((next_expansions, next));
    }

    if let Some(offset) = parse_selector_offset(*tokens.get(i + 1)?, ("saddr", 12), ("daddr", 16)) {
        if let Some((invert, set_idx, next)) = parse_lookup_set_cmp(tokens, i + 2, end) {
            let set = parse_lookup_set_name(*tokens.get(set_idx)?)?;
            let mut ex = expansions;
            push_condition(
                &mut ex,
                NftExpression::Payload(NftPayload::LookupIpv4Addr {
                    offset,
                    set: set.to_string(),
                    invert,
                }),
            );
            return Some((ex, next));
        }

        if tokens.get(i + 2) == Some(&"vmap")
            && tokens.get(i + 3).is_some_and(|t| is_lookup_set_token(t))
        {
            let set = parse_lookup_set_name(*tokens.get(i + 3)?)?;
            let mut ex = expansions;
            push_condition(
                &mut ex,
                NftExpression::Verdict(NftVerdict::VmapLookup {
                    payload_base: nftables::PayloadBase::NetworkHeader,
                    offset,
                    len: 4,
                    set: set.to_string(),
                }),
            );
            return Some((ex, i + 4));
        }

        let (op, values, next) = parse_cmp_values(tokens, i + 2, end)?;
        let next_expansions = expand_conditions(expansions, values, |value| {
            let condition = if let Some((start, end_addr)) = parse_ip_range(value) {
                let (start, end_addr) = match (start, end_addr) {
                    (std::net::IpAddr::V4(start), std::net::IpAddr::V4(end_addr)) => {
                        (start, end_addr)
                    }
                    _ => return None,
                };
                let range_op = cmp_to_range_op(op)?;
                NftExpression::Payload(NftPayload::Ipv4AddrRange {
                    op: range_op,
                    offset,
                    start,
                    end: end_addr,
                })
            } else if let Some((network, mask)) = parse_ip_cidr(value) {
                let network = match network {
                    std::net::IpAddr::V4(network) => network,
                    _ => return None,
                };
                NftExpression::Payload(NftPayload::Ipv4AddrCidr {
                    op,
                    offset,
                    mask: u32::try_from(mask).ok()?,
                    value: u32::from(network),
                })
            } else {
                let addr = parse_token::<std::net::Ipv4Addr>(value)?;
                NftExpression::Payload(NftPayload::Ipv4Addr { op, offset, addr })
            };
            Some(condition)
        })?;
        return Some((next_expansions, next));
    }

    None
}

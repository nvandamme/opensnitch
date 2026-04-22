use netlink_bindings::nftables;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    CT_STATE_ESTABLISHED, CT_STATE_INVALID, CT_STATE_NEW, CT_STATE_RELATED, CT_STATE_UNTRACKED,
    ParsedRuleExpression, RuleAction, RuleCondition, RuleVerdict,
};

impl ParsedRuleExpression {
    pub(super) fn parse_all(expression: &str) -> Option<Vec<Self>> {
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
                    push_condition(
                        &mut expansions,
                        RuleCondition::Ipv4Addr { op, offset, addr },
                    );
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
                    push_condition(
                        &mut expansions,
                        RuleCondition::Ipv6Addr { op, offset, addr },
                    );
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
                    push_condition(
                        &mut expansions,
                        RuleCondition::TransportPort { op, offset, port },
                    );
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

            if i + 2 < end
                && (tokens[i] == "icmp" || tokens[i] == "icmpv6")
                && tokens[i + 1] == "type"
            {
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

fn parse_value_list<'a>(
    tokens: &'a [&'a str],
    start: usize,
    end: usize,
) -> Option<(Vec<&'a str>, usize)> {
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

    Some((
        RuleAction::Queue {
            num: queue_num,
            bypass,
        },
        index,
    ))
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
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
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

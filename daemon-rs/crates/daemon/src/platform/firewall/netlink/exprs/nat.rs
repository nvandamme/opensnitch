use std::net::IpAddr;

use crate::platform::netlink::attrs::{
    NetlinkAttributeBuffer, NetlinkAttributeRecord, finalize_nested_attr, push_attr_header,
    push_nested_attr_header,
};
use netlink_bindings::nftables;

use super::super::{
    NFTA_EXPR_DATA, NFTA_MASQ_FLAGS, NFTA_MASQ_REG_PROTO_MAX, NFTA_MASQ_REG_PROTO_MIN,
    NFTA_REDIR_FLAGS, NFTA_REDIR_REG_PROTO_MAX, NFTA_REDIR_REG_PROTO_MIN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) enum NatType {
    Snat = 0,
    Dnat = 1,
}
use super::NftExpression;
use super::immediate::NftImmediate;
use super::shared::{
    OptionParseStep, normalize_optional_range_pair,
    parse_colon_prefixed_nonempty_single_or_range_token, parse_ip_optional_port_spec_token,
    parse_ip_range, parse_nonempty_single_or_range_token,
    parse_nonempty_single_token_without_range, parse_optional_ip_required_port_spec_token,
    scan_comment_tail, scan_option_sequence,
};

pub(crate) fn parse_masq_action(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    let mut index = start + 1;
    let mut flags = 0_u32;
    let mut proto_min = None;
    let mut proto_max = None;

    index = scan_option_sequence(tokens, index, end, |tokens, index, end| {
        parse_nat_option_step(
            tokens,
            index,
            end,
            &mut flags,
            &mut proto_min,
            &mut proto_max,
            false,
        )
    })?;

    if !validate_nat_random_flags(flags, proto_min.is_some() || proto_max.is_some()) {
        return None;
    }

    Some((
        NftExpression::Nat(NftNat::Masquerade {
            flags,
            proto_min,
            proto_max,
        }),
        index,
    ))
}

pub(crate) fn parse_redirect_action(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    let mut index = start + 1;
    let mut flags = 0_u32;
    let mut proto_min = None;
    let mut proto_max = None;

    index = scan_option_sequence(tokens, index, end, |tokens, index, end| {
        parse_nat_option_step(
            tokens,
            index,
            end,
            &mut flags,
            &mut proto_min,
            &mut proto_max,
            true,
        )
    })?;

    if !validate_nat_random_flags(flags, proto_min.is_some() || proto_max.is_some()) {
        return None;
    }

    Some((
        NftExpression::Nat(NftNat::Redirect {
            flags,
            proto_min,
            proto_max,
        }),
        index,
    ))
}

pub(crate) fn parse_nat_action(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    let nat_type = match tokens.get(start) {
        Some(&"snat") => NatType::Snat,
        Some(&"dnat") => NatType::Dnat,
        _ => return None,
    };

    if tokens.get(start + 1) != Some(&"to") {
        return None;
    }

    let (addr_min, addr_max, proto_min, proto_max) = parse_nat_target(*tokens.get(start + 2)?)?;
    let mut flags = 0_u32;
    if addr_min != addr_max {
        flags |= nftables::NatRangeFlags::MapIps as u32;
    }
    if proto_min.is_some() || proto_max.is_some() {
        flags |= nftables::NatRangeFlags::ProtoSpecified as u32;
    }
    let mut index = start + 3;

    index = scan_option_sequence(tokens, index, end, |tokens, index, _end| {
        parse_nat_flag_step(tokens[index], index, &mut flags).unwrap_or(OptionParseStep::Invalid)
    })?;

    if !validate_nat_random_flags(flags, proto_min.is_some() || proto_max.is_some()) {
        return None;
    }

    Some((
        NftExpression::Nat(NftNat::Nat {
            nat_type,
            addr_min,
            addr_max,
            flags,
            proto_min,
            proto_max,
        }),
        index,
    ))
}

pub(crate) fn parse_tproxy_action(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    if tokens.get(start + 1) != Some(&"to") {
        return None;
    }

    let (addr, port) = parse_tproxy_target(*tokens.get(start + 2)?)?;
    let index = scan_comment_tail(tokens, start + 3, end)?;

    Some((NftExpression::Nat(NftNat::Tproxy { addr, port }), index))
}

pub(crate) fn push_masq_expression<Prev: NetlinkAttributeRecord>(
    exprs: nftables::PushExprListAttrs<Prev>,
    flags: u32,
    proto_min: Option<u16>,
    proto_max: Option<u16>,
) -> nftables::PushExprListAttrs<Prev> {
    let (proto_min, proto_max) = normalize_optional_range_pair(proto_min.zip(proto_max));
    let flags = sanitize_nat_flags(flags, proto_min.is_some());

    let mut exprs = exprs;

    if let Some(min) = proto_min {
        exprs = push_immediate_to_reg(exprs, nftables::Registers::Reg1, &min.to_be_bytes());
    }

    if let Some(max) = proto_max {
        exprs = push_immediate_to_reg(exprs, nftables::Registers::Reg2, &max.to_be_bytes());
    }

    let mut expr = exprs.nested_elem().push_name_bytes(b"masq");
    let data_offset = push_nested_attr_header(expr.attrs_mut(), NFTA_EXPR_DATA);

    if flags != 0 {
        push_attr_header(expr.attrs_mut(), NFTA_MASQ_FLAGS, 4);
        expr.attrs_mut().extend(flags.to_be_bytes());
    }

    if proto_min.is_some() {
        push_attr_header(expr.attrs_mut(), NFTA_MASQ_REG_PROTO_MIN, 4);
        expr.attrs_mut()
            .extend((nftables::Registers::Reg1 as u32).to_be_bytes());
    }

    if proto_max.is_some() {
        push_attr_header(expr.attrs_mut(), NFTA_MASQ_REG_PROTO_MAX, 4);
        expr.attrs_mut()
            .extend((nftables::Registers::Reg2 as u32).to_be_bytes());
    }

    finalize_nested_attr(expr.attrs_mut(), data_offset);
    expr.end_nested()
}

fn push_immediate_to_reg<Prev: NetlinkAttributeRecord>(
    exprs: nftables::PushExprListAttrs<Prev>,
    dreg: nftables::Registers,
    data: &[u8],
) -> nftables::PushExprListAttrs<Prev> {
    NftExpression::Immediate(NftImmediate {
        dreg,
        data: data.to_vec(),
    })
    .encode(exprs)
}

pub(crate) fn push_nat_expression<Prev: NetlinkAttributeRecord>(
    exprs: nftables::PushExprListAttrs<Prev>,
    nat_type: u32,
    addr_min: &std::net::IpAddr,
    addr_max: &std::net::IpAddr,
    flags: u32,
    proto_min: Option<u16>,
    proto_max: Option<u16>,
) -> nftables::PushExprListAttrs<Prev> {
    let (proto_min, proto_max) = normalize_optional_range_pair(proto_min.zip(proto_max));
    let flags = sanitize_nat_flags(flags, proto_min.is_some());

    let (family, addr_min_bytes) = match addr_min {
        std::net::IpAddr::V4(v4) => (2_u32, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (10_u32, v6.octets().to_vec()),
    };

    let addr_max_bytes = match addr_max {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut exprs = exprs
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(nftables::Registers::Reg1 as u32)
        .nested_data()
        .push_value(&addr_min_bytes)
        .end_nested()
        .end_nested()
        .end_nested();

    exprs = exprs
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(nftables::Registers::Reg4 as u32)
        .nested_data()
        .push_value(&addr_max_bytes)
        .end_nested()
        .end_nested()
        .end_nested();

    if let Some(min) = proto_min {
        exprs = exprs
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(nftables::Registers::Reg2 as u32)
            .nested_data()
            .push_value(&min.to_be_bytes())
            .end_nested()
            .end_nested()
            .end_nested();
    }

    if let Some(max) = proto_max {
        exprs = exprs
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(nftables::Registers::Reg3 as u32)
            .nested_data()
            .push_value(&max.to_be_bytes())
            .end_nested()
            .end_nested()
            .end_nested();
    }

    let mut nat_expr = exprs
        .nested_elem()
        .nested_data_nat()
        .push_type(nat_type)
        .push_family(family)
        .push_reg_addr_min(nftables::Registers::Reg1 as u32)
        .push_reg_addr_max(nftables::Registers::Reg4 as u32);

    if proto_min.is_some() {
        nat_expr = nat_expr.push_reg_proto_min(nftables::Registers::Reg2 as u32);
    }

    if proto_max.is_some() {
        nat_expr = nat_expr.push_reg_proto_max(nftables::Registers::Reg3 as u32);
    }

    if flags != 0 {
        nat_expr = nat_expr.push_flags(flags);
    }

    nat_expr.end_nested().end_nested()
}

pub(crate) fn push_redirect_expression<Prev: NetlinkAttributeRecord>(
    exprs: nftables::PushExprListAttrs<Prev>,
    flags: u32,
    proto_min: Option<u16>,
    proto_max: Option<u16>,
) -> nftables::PushExprListAttrs<Prev> {
    let (proto_min, proto_max) = normalize_optional_range_pair(proto_min.zip(proto_max));
    let flags = sanitize_nat_flags(flags, proto_min.is_some());

    let mut exprs = exprs;

    if let Some(min) = proto_min {
        exprs = exprs
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(nftables::Registers::Reg1 as u32)
            .nested_data()
            .push_value(&min.to_be_bytes())
            .end_nested()
            .end_nested()
            .end_nested();
    }

    if let Some(max) = proto_max {
        exprs = exprs
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(nftables::Registers::Reg2 as u32)
            .nested_data()
            .push_value(&max.to_be_bytes())
            .end_nested()
            .end_nested()
            .end_nested();
    }

    let mut expr = exprs.nested_elem().push_name_bytes(b"redir");
    let data_offset = push_nested_attr_header(expr.attrs_mut(), NFTA_EXPR_DATA);

    if proto_min.is_some() {
        push_attr_header(expr.attrs_mut(), NFTA_REDIR_REG_PROTO_MIN, 4);
        expr.attrs_mut()
            .extend((nftables::Registers::Reg1 as u32).to_be_bytes());
    }

    if proto_max.is_some() {
        push_attr_header(expr.attrs_mut(), NFTA_REDIR_REG_PROTO_MAX, 4);
        expr.attrs_mut()
            .extend((nftables::Registers::Reg2 as u32).to_be_bytes());
    }

    if flags != 0 {
        push_attr_header(expr.attrs_mut(), NFTA_REDIR_FLAGS, 4);
        expr.attrs_mut().extend(flags.to_be_bytes());
    }

    finalize_nested_attr(expr.attrs_mut(), data_offset);
    expr.end_nested()
}

pub(crate) fn push_tproxy_expression<Prev: NetlinkAttributeRecord>(
    exprs: nftables::PushExprListAttrs<Prev>,
    addr: Option<&std::net::IpAddr>,
    port: u16,
) -> nftables::PushExprListAttrs<Prev> {
    let mut exprs = exprs
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(nftables::Registers::Reg1 as u32)
        .nested_data()
        .push_value(&port.to_be_bytes())
        .end_nested()
        .end_nested()
        .end_nested();

    let family = match addr {
        Some(std::net::IpAddr::V4(v4)) => {
            exprs = exprs
                .nested_elem()
                .nested_data_immediate()
                .push_dreg(nftables::Registers::Reg2 as u32)
                .nested_data()
                .push_value(&v4.octets())
                .end_nested()
                .end_nested()
                .end_nested();
            2_u32
        }
        Some(std::net::IpAddr::V6(v6)) => {
            exprs = exprs
                .nested_elem()
                .nested_data_immediate()
                .push_dreg(nftables::Registers::Reg2 as u32)
                .nested_data()
                .push_value(&v6.octets())
                .end_nested()
                .end_nested()
                .end_nested();
            10_u32
        }
        None => 2_u32,
    };

    let mut tproxy_expr = exprs
        .nested_elem()
        .nested_data_tproxy()
        .push_family(family)
        .push_reg_port(nftables::Registers::Reg1 as u32);

    if addr.is_some() {
        tproxy_expr = tproxy_expr.push_reg_addr(nftables::Registers::Reg2 as u32);
    }

    tproxy_expr
        .end_nested()
        .end_nested()
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(nftables::Registers::RegVerdict as u32)
        .nested_data()
        .nested_verdict()
        .push_code(nftables::VerdictCode::Accept as u32)
        .end_nested()
        .end_nested()
        .end_nested()
        .end_nested()
}

fn parse_nat_option_step(
    tokens: &[&str],
    index: usize,
    end: usize,
    flags: &mut u32,
    proto_min: &mut Option<u16>,
    proto_max: &mut Option<u16>,
    set_proto_specified: bool,
) -> OptionParseStep {
    if let Some(step) = parse_nat_flag_step(tokens[index], index, flags) {
        return step;
    }

    match tokens[index] {
        "to" => {
            if index + 1 >= end || proto_min.is_some() || proto_max.is_some() {
                return OptionParseStep::Invalid;
            }
            match parse_colon_prefixed_nonempty_single_or_range_token::<u16>(tokens[index + 1]) {
                Some((min, max)) => {
                    *proto_min = Some(min);
                    *proto_max = Some(max);
                    if set_proto_specified {
                        *flags |= nftables::NatRangeFlags::ProtoSpecified as u32;
                    }
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        _ => OptionParseStep::Invalid,
    }
}

fn parse_nat_flag_step(token: &str, index: usize, flags: &mut u32) -> Option<OptionParseStep> {
    Some(match token {
        "random" => {
            *flags |= nftables::NatRangeFlags::ProtoRandom as u32;
            OptionParseStep::Consumed(index + 1)
        }
        "fully-random" => {
            *flags |= nftables::NatRangeFlags::ProtoRandomFully as u32;
            OptionParseStep::Consumed(index + 1)
        }
        "persistent" => {
            *flags |= nftables::NatRangeFlags::Persistent as u32;
            OptionParseStep::Consumed(index + 1)
        }
        "comment" => OptionParseStep::Stop,
        _ => return None,
    })
}

fn parse_tproxy_target(token: &str) -> Option<(Option<IpAddr>, u16)> {
    let (addr, port_spec) = parse_optional_ip_required_port_spec_token(token)?;
    let port = parse_nonempty_single_token_without_range::<u16>(port_spec)?;
    Some((addr, port))
}

fn validate_nat_random_flags(flags: u32, has_proto_spec: bool) -> bool {
    let random = flags & (nftables::NatRangeFlags::ProtoRandom as u32) != 0;
    let fully_random = flags & (nftables::NatRangeFlags::ProtoRandomFully as u32) != 0;

    if random && fully_random {
        return false;
    }

    if (random || fully_random) && !has_proto_spec {
        return false;
    }

    true
}

fn parse_nat_target(token: &str) -> Option<(IpAddr, IpAddr, Option<u16>, Option<u16>)> {
    if let Some((addr, proto_spec)) = parse_ip_optional_port_spec_token(token) {
        if token.starts_with('[') && proto_spec.is_none() {
            return None;
        }

        let (proto_min, proto_max) = normalize_optional_range_pair(
            proto_spec.and_then(parse_nonempty_single_or_range_token::<u16>),
        );
        if proto_spec.is_some() && proto_min.is_none() {
            return None;
        }

        return Some((addr, addr, proto_min, proto_max));
    }

    if let Some((addr_min, addr_max)) = parse_ip_range(token) {
        return Some((addr_min, addr_max, None, None));
    }

    None
}

fn sanitize_nat_flags(flags: u32, has_proto_spec: bool) -> u32 {
    let proto_random = nftables::NatRangeFlags::ProtoRandom as u32;
    let proto_random_fully = nftables::NatRangeFlags::ProtoRandomFully as u32;

    let mut out = flags;
    let has_random = out & proto_random != 0;
    let has_fully_random = out & proto_random_fully != 0;

    if has_random && has_fully_random {
        out &= !(proto_random | proto_random_fully);
    }

    if !has_proto_spec {
        out &= !(proto_random | proto_random_fully);
    }

    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) enum NftNat {
    Masquerade {
        flags: u32,
        proto_min: Option<u16>,
        proto_max: Option<u16>,
    },
    Redirect {
        flags: u32,
        proto_min: Option<u16>,
        proto_max: Option<u16>,
    },
    Tproxy {
        addr: Option<IpAddr>,
        port: u16,
    },
    Nat {
        nat_type: NatType,
        addr_min: IpAddr,
        addr_max: IpAddr,
        flags: u32,
        proto_min: Option<u16>,
        proto_max: Option<u16>,
    },
}

impl NftNat {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::Masquerade {
                flags,
                proto_min,
                proto_max,
            } => push_masq_expression(exprs, *flags, *proto_min, *proto_max),
            Self::Redirect {
                flags,
                proto_min,
                proto_max,
            } => push_redirect_expression(exprs, *flags, *proto_min, *proto_max),
            Self::Tproxy { addr, port } => push_tproxy_expression(exprs, addr.as_ref(), *port),
            Self::Nat {
                nat_type,
                addr_min,
                addr_max,
                flags,
                proto_min,
                proto_max,
            } => push_nat_expression(
                exprs,
                *nat_type as u32,
                addr_min,
                addr_max,
                *flags,
                *proto_min,
                *proto_max,
            ),
        }
    }
}

use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

use super::NftExpression;
use super::shared::{
    parse_cmp_mapped_conditions, parse_eq_neq_mapped_string_conditions, parse_ifname,
    parse_named_value, parse_unsigned_token, push_fib_cmp_from_result,
};

const FIB_RESULT_NAMES: &[(&str, nftables::FibResult)] = &[
    ("oif", nftables::FibResult::Oif),
    ("type", nftables::FibResult::Addrtype),
    ("addrtype", nftables::FibResult::Addrtype),
];

const FIB_SOURCE_FLAG_NAMES: &[(&str, u32)] = &[
    ("saddr", nftables::FibFlags::Saddr as u32),
    ("daddr", nftables::FibFlags::Daddr as u32),
];

const FIB_SECONDARY_FLAG_NAMES: &[(&str, u32)] = &[
    ("iif", nftables::FibFlags::Iif as u32),
    ("oif", nftables::FibFlags::Oif as u32),
    ("mark", nftables::FibFlags::Mark as u32),
    ("present", nftables::FibFlags::Present as u32),
];

pub(crate) fn parse_fib_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"fib") || tokens.get(i + 2) != Some(&".") {
        return None;
    }

    let flags = parse_fib_flags(*tokens.get(i + 1)?, *tokens.get(i + 3)?)?;
    if tokens.get(i + 4) == Some(&"oifname") {
        return parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 5,
            end,
            expansions,
            parse_ifname,
            |op, ifname| NftExpression::Fib(NftFib::Oifname { op, flags, ifname }),
        );
    }

    let result = parse_fib_result(*tokens.get(i + 4)?)?;
    parse_cmp_mapped_conditions(
        tokens,
        i + 5,
        end,
        expansions,
        parse_unsigned_token::<u32>,
        |op, value| {
            NftExpression::Fib(NftFib::Cmp {
                op,
                result,
                flags,
                value,
            })
        },
    )
}

fn parse_fib_result(token: &str) -> Option<nftables::FibResult> {
    parse_named_value(token, FIB_RESULT_NAMES, |_| None)
}

fn parse_fib_flags(source_token: &str, secondary_token: &str) -> Option<u32> {
    let source_flag = parse_named_value(
        source_token,
        FIB_SOURCE_FLAG_NAMES,
        parse_unsigned_token::<u32>,
    )?;
    let secondary_flag = parse_named_value(
        secondary_token,
        FIB_SECONDARY_FLAG_NAMES,
        parse_unsigned_token::<u32>,
    )?;

    Some(source_flag | secondary_flag)
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) enum NftFib {
    Cmp {
        op: nftables::CmpOps,
        result: nftables::FibResult,
        flags: u32,
        value: u32,
    },
    Oifname {
        op: nftables::CmpOps,
        flags: u32,
        ifname: String,
    },
}

impl NftFib {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::Cmp {
                op,
                result,
                flags,
                value,
            } => push_fib_cmp_from_result(exprs, *result as u32, *flags, *op, &value.to_be_bytes()),
            Self::Oifname { op, flags, ifname } => push_fib_cmp_from_result(
                exprs,
                nftables::FibResult::Oifname as u32,
                *flags,
                *op,
                ifname.as_bytes(),
            ),
        }
    }
}

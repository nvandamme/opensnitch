use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

use super::NftExpression;
use super::shared::{
    parse_named_value, parse_unsigned_token, push_lookup_from_reg1, push_payload_load_to_reg1,
};

pub(crate) fn parse_reject_action(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    if start >= end || tokens[start] != "reject" {
        return None;
    }

    if start + 1 >= end || tokens[start + 1] == "comment" {
        return Some((
            NftExpression::Verdict(NftVerdict::Reject {
                reject_type: nftables::RejectTypes::IcmpxUnreach,
                icmp_code: Some(nftables::RejectInetCode::IcmpxPortUnreach as u8),
            }),
            start + 1,
        ));
    }

    if start + 3 < end
        && tokens[start + 1] == "with"
        && tokens[start + 2] == "tcp"
        && tokens[start + 3] == "reset"
    {
        return Some((
            NftExpression::Verdict(NftVerdict::Reject {
                reject_type: nftables::RejectTypes::TcpRst,
                icmp_code: None,
            }),
            start + 4,
        ));
    }

    if start + 4 < end
        && tokens[start + 1] == "with"
        && tokens[start + 2] == "icmpx"
        && tokens[start + 3] == "type"
    {
        let code = parse_reject_icmpx_code(tokens[start + 4])?;
        return Some((
            NftExpression::Verdict(NftVerdict::Reject {
                reject_type: nftables::RejectTypes::IcmpxUnreach,
                icmp_code: Some(code),
            }),
            start + 5,
        ));
    }

    None
}

fn parse_reject_icmpx_code(token: &str) -> Option<u8> {
    parse_named_value(
        token,
        &[
            (
                "icmpx-no-route",
                nftables::RejectInetCode::IcmpxNoRoute as u8,
            ),
            ("no-route", nftables::RejectInetCode::IcmpxNoRoute as u8),
            (
                "icmpx-port-unreach",
                nftables::RejectInetCode::IcmpxPortUnreach as u8,
            ),
            (
                "port-unreachable",
                nftables::RejectInetCode::IcmpxPortUnreach as u8,
            ),
            (
                "icmpx-host-unreach",
                nftables::RejectInetCode::IcmpxHostUnreach as u8,
            ),
            (
                "host-unreachable",
                nftables::RejectInetCode::IcmpxHostUnreach as u8,
            ),
            (
                "icmpx-admin-prohibited",
                nftables::RejectInetCode::IcmpxAdminProhibited as u8,
            ),
            (
                "admin-prohibited",
                nftables::RejectInetCode::IcmpxAdminProhibited as u8,
            ),
        ],
        parse_unsigned_token::<u8>,
    )
}

fn push_verdict_code<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    code: nftables::VerdictCode,
) -> nftables::PushExprListAttrs<Prev> {
    exprs
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(nftables::Registers::RegVerdict as u32)
        .nested_data()
        .nested_verdict()
        .push_code(code as u32)
        .end_nested()
        .end_nested()
        .end_nested()
        .end_nested()
}

fn push_chain_verdict<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    code: nftables::VerdictCode,
    chain: &str,
) -> nftables::PushExprListAttrs<Prev> {
    exprs
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(nftables::Registers::RegVerdict as u32)
        .nested_data()
        .nested_verdict()
        .push_code(code as u32)
        .push_chain_bytes(chain.as_bytes())
        .end_nested()
        .end_nested()
        .end_nested()
        .end_nested()
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) enum NftVerdict {
    Accept,
    Drop,
    Reject {
        reject_type: nftables::RejectTypes,
        icmp_code: Option<u8>,
    },
    Return,
    Continue,
    Break,
    Jump {
        chain: String,
    },
    Goto {
        chain: String,
    },
    VmapLookup {
        payload_base: nftables::PayloadBase,
        offset: u32,
        len: u32,
        set: String,
    },
}

impl NftVerdict {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::Accept => push_verdict_code(exprs, nftables::VerdictCode::Accept),
            Self::Drop => push_verdict_code(exprs, nftables::VerdictCode::Drop),
            Self::Reject {
                reject_type,
                icmp_code,
            } => {
                let mut reject_expr = exprs.nested_elem().nested_data_reject();
                reject_expr = reject_expr.push_type(*reject_type as u32);
                if let Some(code) = icmp_code {
                    reject_expr = reject_expr.push_icmp_code(*code);
                }
                reject_expr.end_nested().end_nested()
            }
            Self::Return => push_verdict_code(exprs, nftables::VerdictCode::Return),
            Self::Continue => push_verdict_code(exprs, nftables::VerdictCode::Continue),
            Self::Break => push_verdict_code(exprs, nftables::VerdictCode::Break),
            Self::Jump { chain } => push_chain_verdict(exprs, nftables::VerdictCode::Jump, chain),
            Self::Goto { chain } => push_chain_verdict(exprs, nftables::VerdictCode::Goto, chain),
            Self::VmapLookup {
                payload_base,
                offset,
                len,
                set,
            } => push_lookup_from_reg1(
                push_payload_load_to_reg1(exprs, *payload_base as u32, *offset, *len),
                set,
                false,
                Some(nftables::Registers::RegVerdict as u32),
            ),
        }
    }
}

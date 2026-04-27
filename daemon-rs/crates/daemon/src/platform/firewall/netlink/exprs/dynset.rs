use crate::platform::netlink::attrs::{
    NetlinkAttributeBuffer, NetlinkAttributeRecord, finalize_nested_attr, push_attr_header,
    push_nested_attr_header,
};
use netlink_bindings::nftables;

use super::super::{
    NFTA_DYNSET_OP, NFTA_DYNSET_SET_ID, NFTA_DYNSET_SET_NAME, NFTA_DYNSET_SREG,
    NFTA_DYNSET_TIMEOUT, NFTA_EXPR_DATA,
};
use super::NftExpression;
use super::shared::{parse_unsigned_token, push_payload_load_to_reg1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) enum DynsetOp {
    Add = 0,
    Update = 1,
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftDynset {
    pub(super) set_name: String,
    pub(super) set_id: u32,
    pub(super) op: DynsetOp,
    pub(super) sreg: nftables::Registers,
    pub(super) timeout: Option<u64>,
    pub(super) payload_base: u32,
    pub(super) payload_offset: u32,
    pub(super) payload_len: u32,
}

fn parse_timeout_token(token: &str) -> Option<u64> {
    if let Some(rest) = token.strip_suffix('h') {
        return parse_unsigned_token::<u64>(rest).map(|v| v * 3600000);
    }
    if let Some(rest) = token.strip_suffix('m') {
        return parse_unsigned_token::<u64>(rest).map(|v| v * 60000);
    }
    if let Some(rest) = token.strip_suffix('s') {
        return parse_unsigned_token::<u64>(rest).map(|v| v * 1000);
    }
    if let Some(rest) = token.strip_suffix("ms") {
        return parse_unsigned_token::<u64>(rest);
    }
    parse_unsigned_token::<u64>(token).map(|v| v * 1000)
}

struct PayloadSpec {
    base: u32,
    offset: u32,
    len: u32,
}

fn parse_dynset_payload(tokens: &[&str], i: usize, end: usize) -> Option<(PayloadSpec, usize)> {
    if i + 1 >= end {
        return None;
    }

    let (base, offset, len) = match (tokens.get(i)?, tokens.get(i + 1)?) {
        (&"ip", &"saddr") => (nftables::PayloadBase::NetworkHeader as u32, 12_u32, 4_u32),
        (&"ip", &"daddr") => (nftables::PayloadBase::NetworkHeader as u32, 16_u32, 4_u32),
        (&"ip6", &"saddr") => (nftables::PayloadBase::NetworkHeader as u32, 8_u32, 16_u32),
        (&"ip6", &"daddr") => (nftables::PayloadBase::NetworkHeader as u32, 24_u32, 16_u32),
        _ => return None,
    };

    Some((PayloadSpec { base, offset, len }, i + 2))
}

pub(crate) fn parse_dynset_action(
    tokens: &[&str],
    i: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    let op = match tokens.get(i)? {
        &"add" => DynsetOp::Add,
        &"update" => DynsetOp::Update,
        _ => return None,
    };

    let set_token = *tokens.get(i + 1)?;
    let set_name = set_token.strip_prefix('@')?;
    if set_name.is_empty() {
        return None;
    }

    if tokens.get(i + 2) != Some(&"{") {
        return None;
    }

    let (payload, next) = parse_dynset_payload(tokens, i + 3, end)?;

    let mut timeout = None;
    let mut idx = next;

    if tokens.get(idx) == Some(&"timeout") {
        let timeout_token = *tokens.get(idx + 1)?;
        // strip trailing } if present
        let timeout_str = timeout_token.strip_suffix('}').unwrap_or(timeout_token);
        timeout = Some(parse_timeout_token(timeout_str)?);
        idx += 2;
    }

    // consume closing brace if not already consumed
    if tokens.get(idx) == Some(&"}") {
        idx += 1;
    }

    Some((
        NftExpression::Dynset(NftDynset {
            set_name: set_name.to_string(),
            set_id: 0,
            op,
            sreg: nftables::Registers::Reg1,
            timeout,
            payload_base: payload.base,
            payload_offset: payload.offset,
            payload_len: payload.len,
        }),
        idx,
    ))
}

impl NftDynset {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let exprs = push_payload_load_to_reg1(
            exprs,
            self.payload_base,
            self.payload_offset,
            self.payload_len,
        );

        let mut expr = exprs.nested_elem().push_name_bytes(b"dynset");
        let data_offset = push_nested_attr_header(expr.attrs_mut(), NFTA_EXPR_DATA);

        let name_bytes = self.set_name.as_bytes();
        push_attr_header(
            expr.attrs_mut(),
            NFTA_DYNSET_SET_NAME,
            name_bytes.len() as u16 + 1,
        );
        expr.attrs_mut().extend(name_bytes);
        expr.attrs_mut().extend([0_u8]); // null terminator

        push_attr_header(expr.attrs_mut(), NFTA_DYNSET_SET_ID, 4);
        expr.attrs_mut().extend(self.set_id.to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_DYNSET_OP, 4);
        expr.attrs_mut().extend((self.op as u32).to_be_bytes());

        push_attr_header(expr.attrs_mut(), NFTA_DYNSET_SREG, 4);
        expr.attrs_mut().extend((self.sreg as u32).to_be_bytes());

        if let Some(timeout) = self.timeout {
            push_attr_header(expr.attrs_mut(), NFTA_DYNSET_TIMEOUT, 8);
            expr.attrs_mut().extend(timeout.to_be_bytes());
        }

        finalize_nested_attr(expr.attrs_mut(), data_offset);
        expr.end_nested()
    }
}

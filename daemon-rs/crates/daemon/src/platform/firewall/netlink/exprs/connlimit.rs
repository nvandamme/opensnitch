use netlink_bindings::nftables;
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};

use super::NftExpression;
use super::shared::parse_unsigned_token;
use super::super::{NFTA_CONNLIMIT_COUNT, NFTA_CONNLIMIT_FLAGS, NFTA_EXPR_DATA};

const NFT_CONNLIMIT_F_INV: u32 = 1;

pub(crate) fn parse_connlimit_condition(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    if tokens.get(start) != Some(&"ct") || tokens.get(start + 1) != Some(&"count") {
        return None;
    }

    let mut next = start + 2;
    let invert = if tokens.get(next) == Some(&"over") {
        next += 1;
        true
    } else {
        false
    };

    if next >= end {
        return None;
    }

    let count = parse_unsigned_token::<u32>(*tokens.get(next)?)?;
    Some((
        NftExpression::Connlimit(NftConnlimit { count, invert }),
        next + 1,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) struct NftConnlimit {
    pub(super) count: u32,
    pub(super) invert: bool,
}

impl NftConnlimit {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let mut expr = exprs.nested_elem().push_name_bytes(b"connlimit");
        let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

        push_header(expr.as_rec_mut(), NFTA_CONNLIMIT_COUNT, 4);
        expr.as_rec_mut().extend(self.count.to_be_bytes());

        if self.invert {
            push_header(expr.as_rec_mut(), NFTA_CONNLIMIT_FLAGS, 4);
            expr.as_rec_mut()
                .extend(NFT_CONNLIMIT_F_INV.to_be_bytes());
        }

        finalize_nested_header(expr.as_rec_mut(), data_offset);
        expr.end_nested()
    }
}

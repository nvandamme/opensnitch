use netlink_bindings::nftables;
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};
use nix::libc;

use super::super::{NFTA_EXPR_DATA, NFTA_QUEUE_FLAGS, NFTA_QUEUE_NUM, NFTA_QUEUE_TOTAL};
use super::NftExpression;
use super::shared::{OptionParseStep, parse_token, scan_option_sequence};

pub(crate) fn parse_queue_action(tokens: &[&str], start: usize) -> Option<(NftExpression, usize)> {
    let mut queue_num = 0_u16;
    let mut bypass = false;

    let index =
        scan_option_sequence(
            tokens,
            start + 1,
            tokens.len(),
            |tokens, index, end| match tokens[index] {
                "num" if index + 1 < end => match parse_token::<u16>(tokens[index + 1]) {
                    Some(parsed) => {
                        queue_num = parsed;
                        OptionParseStep::Consumed(index + 2)
                    }
                    None => OptionParseStep::Invalid,
                },
                "bypass" => {
                    bypass = true;
                    OptionParseStep::Consumed(index + 1)
                }
                "comment" => OptionParseStep::Stop,
                _ => OptionParseStep::Invalid,
            },
        )?;

    Some((
        NftExpression::Queue(NftQueue {
            num: queue_num,
            bypass,
        }),
        index,
    ))
}

pub(crate) fn push_queue_expression<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    queue_num: u16,
    bypass: bool,
) -> nftables::PushExprListAttrs<Prev> {
    let mut expr = exprs.nested_elem().push_name_bytes(b"queue");
    let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

    push_header(expr.as_rec_mut(), NFTA_QUEUE_NUM, 2);
    expr.as_rec_mut().extend(queue_num.to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_QUEUE_TOTAL, 2);
    expr.as_rec_mut().extend(1_u16.to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_QUEUE_FLAGS, 2);
    let flags = if bypass {
        libc::NFT_QUEUE_FLAG_BYPASS as u16
    } else {
        0
    };
    expr.as_rec_mut().extend(flags.to_be_bytes());

    finalize_nested_header(expr.as_rec_mut(), data_offset);
    expr.end_nested()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) struct NftQueue {
    pub(super) num: u16,
    pub(super) bypass: bool,
}

impl NftQueue {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        push_queue_expression(exprs, self.num, self.bypass)
    }
}

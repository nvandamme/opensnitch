use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;
use nix::libc;

use super::NftExpression;
use super::shared::{OptionParseStep, parse_unsigned_token, scan_option_sequence};

pub(crate) fn parse_quota_condition(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    if tokens.get(start) != Some(&"quota") {
        return None;
    }

    let mut invert = false;
    let mut bytes = None;
    let mut index = start + 1;
    index = scan_option_sequence(tokens, index, end, |tokens, index, end| {
        match tokens[index] {
            "over" => {
                invert = true;
                OptionParseStep::Consumed(index + 1)
            }
            "comment" => OptionParseStep::Stop,
            _ if bytes.is_none() => {
                if index + 1 < end {
                    if let Some(parsed) = parse_quota_bytes(tokens[index], tokens[index + 1]) {
                        bytes = Some(parsed);
                        return OptionParseStep::Consumed(index + 2);
                    }
                }

                if let Some(parsed) = parse_quota_bytes(tokens[index], "bytes") {
                    bytes = Some(parsed);
                    return OptionParseStep::Consumed(index + 1);
                }

                OptionParseStep::Invalid
            }
            _ => OptionParseStep::Stop,
        }
    })?;

    let bytes = bytes?;
    Some((NftExpression::Quota(NftQuota { bytes, invert }), index))
}

fn parse_quota_bytes(value_token: &str, unit_token: &str) -> Option<u64> {
    let value = parse_unsigned_token::<u64>(value_token)?;
    let multiplier = match unit_token {
        "bytes" | "byte" | "b" => 1_u64,
        "kbytes" | "kbyte" | "kb" => 1024_u64,
        "mbytes" | "mbyte" | "mb" => 1024_u64 * 1024_u64,
        "gbytes" | "gbyte" | "gb" => 1024_u64 * 1024_u64 * 1024_u64,
        _ => return None,
    };
    value.checked_mul(multiplier)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) struct NftQuota {
    pub(super) bytes: u64,
    pub(super) invert: bool,
}

impl NftQuota {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let mut expr = exprs
            .nested_elem()
            .nested_data_quota()
            .push_bytes(self.bytes);

        if self.invert {
            expr = expr.push_flags(libc::NFT_QUOTA_F_INV as u32);
        }

        expr.end_nested().end_nested()
    }
}

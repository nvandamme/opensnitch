use netlink_bindings::nftables;
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};
use nix::libc;

use super::super::{
    NFTA_EXPR_DATA, NFTA_LIMIT_BURST, NFTA_LIMIT_FLAGS, NFTA_LIMIT_RATE, NFTA_LIMIT_TYPE,
    NFTA_LIMIT_UNIT,
};
use super::NftExpression;
use super::shared::{OptionParseStep, parse_unsigned_token, scan_option_sequence};

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * 60;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

pub(crate) fn parse_limit_condition(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    if tokens.get(start) != Some(&"limit") {
        return None;
    }

    let mut index = start + 1;
    if tokens.get(index) == Some(&"rate") {
        index += 1;
    }

    let mut invert = false;
    if tokens.get(index) == Some(&"over") {
        invert = true;
        index += 1;
    }

    let mut limit_type = libc::NFT_LIMIT_PKTS as u32;
    let mut unit = 1_u64;
    let mut burst = None::<u32>;
    let rate_token = *tokens.get(index)?;
    let mut rate = if let Some((rate_raw, time_raw)) = rate_token.split_once('/') {
        unit = parse_time_unit_token(time_raw)?;
        parse_unsigned_token::<u64>(rate_raw)?
    } else {
        parse_unsigned_token::<u64>(rate_token)?
    };
    index += 1;

    if let Some(token) = tokens.get(index) {
        if *token != "burst" && *token != "comment" {
            if token.contains('/') {
                let (parsed_type, multiplier, parsed_unit) = parse_rate_time_token(token)?;
                if parsed_type == libc::NFT_LIMIT_PKT_BYTES as u32 {
                    limit_type = parsed_type;
                    rate = rate.checked_mul(multiplier)?;
                }
                unit = parsed_unit;
                index += 1;
            } else {
                let mut parsed_rate_unit = parse_rate_unit_token(token);
                if let Some((parsed_type, multiplier)) = parsed_rate_unit.take() {
                    if parsed_type == libc::NFT_LIMIT_PKT_BYTES as u32 {
                        limit_type = parsed_type;
                        rate = rate.checked_mul(multiplier)?;
                    }
                    index += 1;
                }

                if let Some(time_token) = tokens.get(index) {
                    if *time_token != "burst" && *time_token != "comment" {
                        if let Some(parsed_unit) = parse_time_unit_token(time_token) {
                            unit = parsed_unit;
                            index += 1;
                        }
                    }
                }
            }
        }
    }

    index = scan_option_sequence(tokens, index, end, |tokens, idx, end| match tokens[idx] {
        "burst" if idx + 1 < end => match parse_unsigned_token::<u32>(tokens[idx + 1]) {
            Some(value) => {
                burst = Some(value);
                OptionParseStep::Consumed(idx + 2)
            }
            None => OptionParseStep::Invalid,
        },
        "comment" => OptionParseStep::Stop,
        _ => OptionParseStep::Stop,
    })?;

    Some((
        NftExpression::Limit(NftLimit {
            rate,
            unit,
            burst,
            limit_type,
            invert,
        }),
        index,
    ))
}

fn parse_rate_time_token(token: &str) -> Option<(u32, u64, u64)> {
    let (rate_unit_raw, time_unit_raw) = token.split_once('/')?;
    let (limit_type, multiplier) = parse_rate_unit_token(&rate_unit_raw.to_ascii_lowercase())?;
    let time_unit = parse_time_unit_token(&time_unit_raw.to_ascii_lowercase())?;
    Some((limit_type, multiplier, time_unit))
}

fn parse_rate_unit_token(token: &str) -> Option<(u32, u64)> {
    Some(match token.to_ascii_lowercase().as_str() {
        "packet" | "packets" | "pkt" | "pkts" => (libc::NFT_LIMIT_PKTS as u32, 1),
        "byte" | "bytes" | "b" => (libc::NFT_LIMIT_PKT_BYTES as u32, 1),
        "kbyte" | "kbytes" | "kb" => (libc::NFT_LIMIT_PKT_BYTES as u32, 1024),
        "mbyte" | "mbytes" | "mb" => (libc::NFT_LIMIT_PKT_BYTES as u32, 1024 * 1024),
        "gbyte" | "gbytes" | "gb" => (libc::NFT_LIMIT_PKT_BYTES as u32, 1024 * 1024 * 1024),
        _ => return None,
    })
}

fn parse_time_unit_token(token: &str) -> Option<u64> {
    Some(match token.to_ascii_lowercase().as_str() {
        "second" | "seconds" | "sec" | "s" => 1,
        "minute" | "minutes" | "min" | "m" => SECONDS_PER_MINUTE,
        "hour" | "hours" | "h" => SECONDS_PER_HOUR,
        "day" | "days" | "d" => SECONDS_PER_DAY,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) struct NftLimit {
    pub(super) rate: u64,
    pub(super) unit: u64,
    pub(super) burst: Option<u32>,
    pub(super) limit_type: u32,
    pub(super) invert: bool,
}

impl NftLimit {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let mut expr = exprs.nested_elem().push_name_bytes(b"limit");
        let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

        push_header(expr.as_rec_mut(), NFTA_LIMIT_RATE, 8);
        expr.as_rec_mut().extend(self.rate.to_be_bytes());

        push_header(expr.as_rec_mut(), NFTA_LIMIT_UNIT, 8);
        expr.as_rec_mut().extend(self.unit.to_be_bytes());

        push_header(expr.as_rec_mut(), NFTA_LIMIT_TYPE, 4);
        expr.as_rec_mut().extend(self.limit_type.to_be_bytes());

        if let Some(burst) = self.burst {
            push_header(expr.as_rec_mut(), NFTA_LIMIT_BURST, 4);
            expr.as_rec_mut().extend(burst.to_be_bytes());
        }

        if self.invert {
            push_header(expr.as_rec_mut(), NFTA_LIMIT_FLAGS, 4);
            expr.as_rec_mut()
                .extend((libc::NFT_LIMIT_F_INV as u32).to_be_bytes());
        }

        finalize_nested_header(expr.as_rec_mut(), data_offset);
        expr.end_nested()
    }
}

use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

use super::NftExpression;
use super::shared::{
    OptionParseStep, parse_named_bitmask_value, parse_named_value, parse_quoted_ascii_symbol_token,
    parse_unsigned_token, scan_option_sequence,
};

const LOG_LEVEL_NAMES: &[(&str, nftables::LogLevel)] = &[
    ("emerg", nftables::LogLevel::Emerg),
    ("alert", nftables::LogLevel::Alert),
    ("crit", nftables::LogLevel::Crit),
    ("critical", nftables::LogLevel::Crit),
    ("err", nftables::LogLevel::Err),
    ("error", nftables::LogLevel::Err),
    ("warning", nftables::LogLevel::Warning),
    ("warn", nftables::LogLevel::Warning),
    ("notice", nftables::LogLevel::Notice),
    ("info", nftables::LogLevel::Info),
    ("debug", nftables::LogLevel::Debug),
    ("audit", nftables::LogLevel::Audit),
];

const LOG_FLAG_NAMES: &[(&str, u32)] = &[
    ("tcpseq", nftables::LogFlags::Tcpseq as u32),
    ("tcpopt", nftables::LogFlags::Tcpopt as u32),
    ("ipopt", nftables::LogFlags::Ipopt as u32),
    ("uid", nftables::LogFlags::Uid as u32),
    ("nflog", nftables::LogFlags::Nflog as u32),
    ("macdecode", nftables::LogFlags::Macdecode as u32),
];

pub(crate) fn parse_log_condition(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    if start >= end || tokens[start] != "log" {
        return None;
    }

    let mut i = start + 1;
    let mut group = None;
    let mut prefix = None;
    let mut snaplen = None;
    let mut qthreshold = None;
    let mut level = None;
    let mut flags = None;
    i = scan_option_sequence(tokens, i, end, |tokens, index, end| match tokens[index] {
        "group" => {
            if index + 1 >= end {
                return OptionParseStep::Invalid;
            }
            match parse_unsigned_token::<u16>(tokens[index + 1]) {
                Some(value) => {
                    group = Some(value);
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        "prefix" => {
            if index + 1 >= end {
                return OptionParseStep::Invalid;
            }
            match parse_quoted_ascii_symbol_token(
                tokens[index + 1],
                64,
                &['_', '-', '.', ':', '+', '/'],
            ) {
                Some(value) => {
                    prefix = Some(value.to_string());
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        "snaplen" => {
            if index + 1 >= end {
                return OptionParseStep::Invalid;
            }
            match parse_unsigned_token::<u32>(tokens[index + 1]) {
                Some(value) => {
                    snaplen = Some(value);
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        "qthreshold" | "queue-threshold" => {
            if index + 1 >= end {
                return OptionParseStep::Invalid;
            }
            match parse_unsigned_token::<u16>(tokens[index + 1]) {
                Some(value) => {
                    qthreshold = Some(value);
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        "level" => {
            if index + 1 >= end {
                return OptionParseStep::Invalid;
            }
            match parse_log_level(tokens[index + 1]) {
                Some(value) => {
                    level = Some(value);
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        "flags" => {
            if index + 1 >= end {
                return OptionParseStep::Invalid;
            }
            match parse_log_flags(tokens[index + 1]) {
                Some(value) => {
                    flags = Some(value);
                    OptionParseStep::Consumed(index + 2)
                }
                None => OptionParseStep::Invalid,
            }
        }
        _ => OptionParseStep::Stop,
    })?;

    Some((
        NftExpression::Log(NftLog {
            group,
            prefix,
            snaplen,
            qthreshold,
            level,
            flags,
        }),
        i,
    ))
}

fn parse_log_level(token: &str) -> Option<nftables::LogLevel> {
    parse_named_value(token, LOG_LEVEL_NAMES, |_| None)
}

fn parse_log_flags(token: &str) -> Option<u32> {
    parse_named_bitmask_value(token, LOG_FLAG_NAMES)
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftLog {
    pub(super) group: Option<u16>,
    pub(super) prefix: Option<String>,
    pub(super) snaplen: Option<u32>,
    pub(super) qthreshold: Option<u16>,
    pub(super) level: Option<nftables::LogLevel>,
    pub(super) flags: Option<u32>,
}

impl NftLog {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let mut log_expr = exprs.nested_elem().nested_data_log();
        if let Some(group) = self.group {
            log_expr = log_expr.push_group(group);
        }
        if let Some(prefix) = &self.prefix {
            log_expr = log_expr.push_prefix_bytes(prefix.as_bytes());
        }
        if let Some(snaplen) = self.snaplen {
            log_expr = log_expr.push_snaplen(snaplen);
        }
        if let Some(qthreshold) = self.qthreshold {
            log_expr = log_expr.push_qthreshold(qthreshold);
        }
        if let Some(level) = self.level {
            log_expr = log_expr.push_level(level as u32);
        }
        if let Some(flags) = self.flags {
            log_expr = log_expr.push_flags(flags);
        }
        log_expr.end_nested().end_nested()
    }
}

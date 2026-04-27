use std::collections::BTreeMap;

use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

use super::shared::parse_ascii_symbol_token;
use super::{NftExpression, NftRule};

pub(crate) fn parse_counter_condition(
    tokens: &[&str],
    start: usize,
    end: usize,
) -> Option<(NftExpression, usize)> {
    let mut index = start + 1;
    let mut name = None;
    let mut packets = false;
    let mut bytes = false;

    while index < end {
        match tokens[index] {
            "name" if index + 1 < end => {
                name = Some(
                    parse_ascii_symbol_token(tokens[index + 1], 32, &['_', '-', '.'])?.to_string(),
                );
                index += 2;
            }
            "packets" => {
                packets = true;
                index += 1;
            }
            "bytes" => {
                bytes = true;
                index += 1;
            }
            _ => break,
        }
    }

    Some((
        NftExpression::Counter(NftCounter {
            name: name.unwrap_or_else(|| "opensnitch".to_string()),
            packets,
            bytes,
        }),
        index,
    ))
}

pub(in crate::platform::firewall::netlink) fn collect_counter_object_specs(
    parsed_rules: &[NftRule],
) -> BTreeMap<String, (bool, bool)> {
    let mut counters = BTreeMap::new();

    for parsed in parsed_rules {
        for expression in &parsed.expressions {
            if let NftExpression::Counter(NftCounter {
                name,
                packets,
                bytes,
            }) = expression
            {
                let entry = counters.entry(name.clone()).or_insert((false, false));
                entry.0 |= *packets;
                entry.1 |= *bytes;
            }
        }
    }

    counters
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftCounter {
    pub(super) name: String,
    pub(super) packets: bool,
    pub(super) bytes: bool,
}

impl NftCounter {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        exprs
            .nested_elem()
            .nested_data_objref()
            .push_imm_type(nftables::ObjectType::Counter as u32)
            .push_imm_name_bytes(self.name.as_bytes())
            .end_nested()
            .end_nested()
    }
}

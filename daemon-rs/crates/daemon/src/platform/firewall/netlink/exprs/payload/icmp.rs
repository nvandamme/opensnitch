use super::super::NftExpression;
use super::super::shared::{
    expand_conditions, parse_icmp_type, parse_proto, parse_unsigned_token, parse_value_list,
};
use super::{NftPayload, PayloadParseResult};

pub(super) fn parse_icmp_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<PayloadParseResult> {
    let proto = parse_proto(*tokens.get(i)?)?;
    let selector = *tokens.get(i + 1)?;
    let (values, next) = parse_value_list(tokens, i + 2, end)?;
    let next_expansions = match selector {
        "type" => expand_conditions(expansions, values, |value| {
            let type_code = parse_icmp_type(tokens.get(i) == Some(&"icmpv6"), value)?;
            Some(NftExpression::Payload(NftPayload::IcmpType {
                proto,
                type_code,
            }))
        })?,
        "code" => expand_conditions(expansions, values, |value| {
            let code = parse_unsigned_token::<u8>(value)?;
            Some(NftExpression::Payload(NftPayload::IcmpCode { proto, code }))
        })?,
        "checksum" => expand_conditions(expansions, values, |value| {
            let checksum = parse_unsigned_token::<u16>(value)?;
            Some(NftExpression::Payload(NftPayload::IcmpChecksum {
                proto,
                checksum,
            }))
        })?,
        _ => return None,
    };
    Some((next_expansions, next))
}

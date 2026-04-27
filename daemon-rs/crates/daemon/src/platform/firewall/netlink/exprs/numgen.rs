use super::NftExpression;
use super::shared::{parse_cmp_mapped_conditions, parse_unsigned_token, push_numgen_cmp};
use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

pub(crate) fn parse_numgen_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"numgen") {
        return None;
    }

    let gen_type = parse_numgen_type(*tokens.get(i + 1)?)?;
    if tokens.get(i + 2) != Some(&"mod") {
        return None;
    }

    let modulus = parse_unsigned_token::<u32>(*tokens.get(i + 3)?)?;
    if modulus == 0 {
        return None;
    }

    let (offset, cmp_start) = if tokens.get(i + 4) == Some(&"offset") {
        (parse_unsigned_token::<u32>(*tokens.get(i + 5)?)?, i + 6)
    } else {
        (0_u32, i + 4)
    };

    parse_cmp_mapped_conditions(
        tokens,
        cmp_start,
        end,
        expansions,
        parse_unsigned_token::<u32>,
        |op, value| {
            NftExpression::Numgen(NftNumgen {
                op,
                gen_type,
                modulus,
                offset,
                value,
            })
        },
    )
}

fn parse_numgen_type(token: &str) -> Option<nftables::NumgenTypes> {
    Some(match token {
        "inc" | "incremental" => nftables::NumgenTypes::Incremental,
        "random" => nftables::NumgenTypes::Random,
        _ => return None,
    })
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftNumgen {
    pub(super) op: nftables::CmpOps,
    pub(super) gen_type: nftables::NumgenTypes,
    pub(super) modulus: u32,
    pub(super) offset: u32,
    pub(super) value: u32,
}

impl NftNumgen {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        push_numgen_cmp(
            exprs,
            self.gen_type as u32,
            self.modulus,
            self.offset,
            self.op,
            &self.value.to_be_bytes(),
        )
    }
}

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_bindings::nftables;
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};

use super::NftExpression;
use super::shared::{
    parse_cmp_and_value_index, parse_token, parse_unsigned_token,
    push_condition,
};
use super::super::{NFTA_EXPR_DATA, NFTA_RT_DREG, NFTA_RT_KEY};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) enum RtKey {
    Classid = 0,
    Nexthop4 = 1,
    Nexthop6 = 2,
    TcpMss = 3,
    Ipsec = 4,
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftRt {
    pub(super) key: RtKey,
    pub(super) dreg: nftables::Registers,
}

pub(crate) fn parse_rt_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    mut expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"rt") {
        return None;
    }

    let subkey = *tokens.get(i + 1)?;
    match subkey {
        "classid" => {
            let (op, value_idx) = parse_cmp_and_value_index(tokens, i + 2, end)?;
            let value = parse_unsigned_token::<u32>(*tokens.get(value_idx)?)?;
            let rt = NftRt {
                key: RtKey::Classid,
                dreg: nftables::Registers::Reg1,
            };
            push_condition(&mut expansions, NftExpression::Rt(rt));
            push_condition(
                &mut expansions,
                NftExpression::Cmp(super::cmp::NftCmp {
                    sreg: nftables::Registers::Reg1,
                    op,
                    data: value.to_be_bytes().to_vec(),
                }),
            );
            Some((expansions, value_idx + 1))
        }
        "mtu" => {
            let (op, value_idx) = parse_cmp_and_value_index(tokens, i + 2, end)?;
            let value = parse_unsigned_token::<u32>(*tokens.get(value_idx)?)?;
            let rt = NftRt {
                key: RtKey::TcpMss,
                dreg: nftables::Registers::Reg1,
            };
            push_condition(&mut expansions, NftExpression::Rt(rt));
            push_condition(
                &mut expansions,
                NftExpression::Cmp(super::cmp::NftCmp {
                    sreg: nftables::Registers::Reg1,
                    op,
                    data: value.to_be_bytes().to_vec(),
                }),
            );
            Some((expansions, value_idx + 1))
        }
        "nexthop" => {
            let (op, value_idx) = parse_cmp_and_value_index(tokens, i + 2, end)?;
            let addr_token = *tokens.get(value_idx)?;

            if let Some(v4) = parse_token::<Ipv4Addr>(addr_token) {
                let rt = NftRt {
                    key: RtKey::Nexthop4,
                    dreg: nftables::Registers::Reg1,
                };
                push_condition(&mut expansions, NftExpression::Rt(rt));
                push_condition(
                    &mut expansions,
                    NftExpression::Cmp(super::cmp::NftCmp {
                        sreg: nftables::Registers::Reg1,
                        op,
                        data: v4.octets().to_vec(),
                    }),
                );
                Some((expansions, value_idx + 1))
            } else if let Some(v6) = parse_token::<Ipv6Addr>(addr_token) {
                let rt = NftRt {
                    key: RtKey::Nexthop6,
                    dreg: nftables::Registers::Reg1,
                };
                push_condition(&mut expansions, NftExpression::Rt(rt));
                push_condition(
                    &mut expansions,
                    NftExpression::Cmp(super::cmp::NftCmp {
                        sreg: nftables::Registers::Reg1,
                        op,
                        data: v6.octets().to_vec(),
                    }),
                );
                Some((expansions, value_idx + 1))
            } else {
                None
            }
        }
        "ipsec" => {
            if tokens.get(i + 2) != Some(&"exists") {
                return None;
            }
            let rt = NftRt {
                key: RtKey::Ipsec,
                dreg: nftables::Registers::Reg1,
            };
            push_condition(&mut expansions, NftExpression::Rt(rt));
            push_condition(
                &mut expansions,
                NftExpression::Cmp(super::cmp::NftCmp {
                    sreg: nftables::Registers::Reg1,
                    op: nftables::CmpOps::Eq,
                    data: 1_u32.to_be_bytes().to_vec(),
                }),
            );
            Some((expansions, i + 3))
        }
        _ => None,
    }
}

fn push_rt_expression<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    key: RtKey,
    dreg: nftables::Registers,
) -> nftables::PushExprListAttrs<Prev> {
    let mut expr = exprs.nested_elem().push_name_bytes(b"rt");
    let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

    push_header(expr.as_rec_mut(), NFTA_RT_DREG, 4);
    expr.as_rec_mut().extend((dreg as u32).to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_RT_KEY, 4);
    expr.as_rec_mut().extend((key as u32).to_be_bytes());

    finalize_nested_header(expr.as_rec_mut(), data_offset);
    expr.end_nested()
}

impl NftRt {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        push_rt_expression(exprs, self.key, self.dreg)
    }
}

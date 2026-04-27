use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::{conntrack, nftables};

use super::NftExpression;
use super::bitwise::NftBitwise;
use super::shared::{
    parse_cmp_mapped_conditions, parse_eq_mask_condition, parse_kind_token, parse_nfproto,
    parse_proto, parse_token, parse_unsigned_token, push_cmp_from_reg1, push_ct_cmp_from_key,
};

pub(crate) fn parse_ct_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    mut expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"ct") {
        return None;
    }

    match tokens.get(i + 1) {
        Some(&"state") => {
            let next = parse_eq_mask_condition(
                tokens,
                i + 2,
                end,
                &mut expansions,
                ct_state_mask,
                |mask| NftExpression::Ct(NftCt::StateMask { mask }),
            )?;
            Some((expansions, next))
        }
        Some(&"status") => {
            let next = parse_eq_mask_condition(
                tokens,
                i + 2,
                end,
                &mut expansions,
                ct_status_mask,
                |mask| NftExpression::Ct(NftCt::StatusMask { mask }),
            )?;
            Some((expansions, next))
        }
        Some(&"direction") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_ct_direction,
            |op, direction| NftExpression::Ct(NftCt::Direction { op, direction }),
        ),
        Some(&"mark") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Ct(NftCt::Mark { op, mark: value }),
        ),
        Some(&"secmark") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Ct(NftCt::Secmark { op, secmark: value }),
        ),
        Some(&"expiration") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| {
                NftExpression::Ct(NftCt::Expiration {
                    op,
                    expiration: value,
                })
            },
        ),
        Some(&"l3protocol") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_nfproto,
            |op, l3protocol| NftExpression::Ct(NftCt::L3Protocol { op, l3protocol }),
        ),
        Some(&"protocol") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_proto,
            |op, protocol| NftExpression::Ct(NftCt::Protocol { op, protocol }),
        ),
        Some(&"proto-src") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, value| {
                NftExpression::Ct(NftCt::ProtoSrc {
                    op,
                    proto_src: value,
                })
            },
        ),
        Some(&"proto-dst") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, value| {
                NftExpression::Ct(NftCt::ProtoDst {
                    op,
                    proto_dst: value,
                })
            },
        ),
        Some(&"zone") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, value| NftExpression::Ct(NftCt::Zone { op, zone: value }),
        ),
        Some(&"helper") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_kind_token,
            |op, helper| {
                NftExpression::Ct(NftCt::Helper {
                    op,
                    helper: helper.to_string(),
                })
            },
        ),
        Some(&"src") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Ct(NftCt::Src { op, src: value }),
        ),
        Some(&"dst") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Ct(NftCt::Dst { op, dst: value }),
        ),
        Some(&"src-ip") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_token::<std::net::Ipv4Addr>,
            |op, addr| NftExpression::Ct(NftCt::SrcIp { op, addr }),
        ),
        Some(&"dst-ip") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_token::<std::net::Ipv4Addr>,
            |op, addr| NftExpression::Ct(NftCt::DstIp { op, addr }),
        ),
        Some(&"src-ip6") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_token::<std::net::Ipv6Addr>,
            |op, addr| NftExpression::Ct(NftCt::SrcIp6 { op, addr }),
        ),
        Some(&"dst-ip6") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_token::<std::net::Ipv6Addr>,
            |op, addr| NftExpression::Ct(NftCt::DstIp6 { op, addr }),
        ),
        Some(&"pkts") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u64>,
            |op, value| NftExpression::Ct(NftCt::Pkts { op, pkts: value }),
        ),
        Some(&"bytes") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u64>,
            |op, value| NftExpression::Ct(NftCt::Bytes { op, bytes: value }),
        ),
        Some(&"avgpkt") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u64>,
            |op, value| NftExpression::Ct(NftCt::Avgpkt { op, avgpkt: value }),
        ),
        Some(&"eventmask") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| {
                NftExpression::Ct(NftCt::Eventmask {
                    op,
                    eventmask: value,
                })
            },
        ),
        Some(&"id") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Ct(NftCt::Id { op, ct_id: value }),
        ),
        _ => None,
    }
}

fn push_ct_mask_condition<Prev: NetlinkAttributeRecord>(
    exprs: nftables::PushExprListAttrs<Prev>,
    key: nftables::CtKeys,
    mask: u32,
) -> nftables::PushExprListAttrs<Prev> {
    let exprs = exprs
        .nested_elem()
        .nested_data_ct()
        .push_dreg(nftables::Registers::Reg1 as u32)
        .push_key(key as u32)
        .end_nested()
        .end_nested();
    let exprs = NftExpression::Bitwise(NftBitwise {
        sreg: nftables::Registers::Reg1,
        dreg: nftables::Registers::Reg1,
        mask: mask.to_be_bytes().to_vec(),
        xor: 0_u32.to_be_bytes().to_vec(),
    })
    .encode(exprs);

    push_cmp_from_reg1(exprs, nftables::CmpOps::Neq, &0_u32.to_be_bytes())
}

fn ct_state_mask(state: &str) -> Option<u32> {
    match state {
        "invalid" => Some(CtStateBit::Invalid as u32),
        "established" => Some(CtStateBit::Established as u32),
        "related" => Some(CtStateBit::Related as u32),
        "new" => Some(CtStateBit::New as u32),
        "untracked" => Some(CtStateBit::Untracked as u32),
        _ => None,
    }
}

fn ct_status_mask(status: &str) -> Option<u32> {
    match status {
        "expected" => Some(conntrack::NfCtStatus::Expected as u32),
        "seen-reply" | "seen_reply" => Some(conntrack::NfCtStatus::SeenReply as u32),
        "assured" => Some(conntrack::NfCtStatus::Assured as u32),
        "confirmed" => Some(conntrack::NfCtStatus::Confirmed as u32),
        "snat" => Some(conntrack::NfCtStatus::SrcNat as u32),
        "dnat" => Some(conntrack::NfCtStatus::DstNat as u32),
        _ => None,
    }
}

fn parse_ct_direction(token: &str) -> Option<u8> {
    match token {
        "original" => Some(nftables::CtDirection::Original as u8),
        "reply" => Some(nftables::CtDirection::Reply as u8),
        _ => parse_token::<u8>(token).and_then(|value| {
            nftables::CtDirection::from_value(u64::from(value)).map(|direction| direction as u8)
        }),
    }
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) enum NftCt {
    StateMask {
        mask: u32,
    },
    StatusMask {
        mask: u32,
    },
    Direction {
        op: nftables::CmpOps,
        direction: u8,
    },
    Mark {
        op: nftables::CmpOps,
        mark: u32,
    },
    Secmark {
        op: nftables::CmpOps,
        secmark: u32,
    },
    Expiration {
        op: nftables::CmpOps,
        expiration: u32,
    },
    L3Protocol {
        op: nftables::CmpOps,
        l3protocol: u8,
    },
    Protocol {
        op: nftables::CmpOps,
        protocol: u8,
    },
    ProtoSrc {
        op: nftables::CmpOps,
        proto_src: u16,
    },
    ProtoDst {
        op: nftables::CmpOps,
        proto_dst: u16,
    },
    Zone {
        op: nftables::CmpOps,
        zone: u16,
    },
    Helper {
        op: nftables::CmpOps,
        helper: String,
    },
    Src {
        op: nftables::CmpOps,
        src: u32,
    },
    Dst {
        op: nftables::CmpOps,
        dst: u32,
    },
    SrcIp {
        op: nftables::CmpOps,
        addr: std::net::Ipv4Addr,
    },
    DstIp {
        op: nftables::CmpOps,
        addr: std::net::Ipv4Addr,
    },
    SrcIp6 {
        op: nftables::CmpOps,
        addr: std::net::Ipv6Addr,
    },
    DstIp6 {
        op: nftables::CmpOps,
        addr: std::net::Ipv6Addr,
    },
    Pkts {
        op: nftables::CmpOps,
        pkts: u64,
    },
    Bytes {
        op: nftables::CmpOps,
        bytes: u64,
    },
    Avgpkt {
        op: nftables::CmpOps,
        avgpkt: u64,
    },
    Eventmask {
        op: nftables::CmpOps,
        eventmask: u32,
    },
    Id {
        op: nftables::CmpOps,
        ct_id: u32,
    },
}

impl NftCt {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::StateMask { mask } => {
                push_ct_mask_condition(exprs, nftables::CtKeys::State, *mask)
            }
            Self::StatusMask { mask } => {
                push_ct_mask_condition(exprs, nftables::CtKeys::Status, *mask)
            }
            Self::Direction { op, direction } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Direction, *op, &[*direction])
            }
            Self::Mark { op, mark } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Mark, *op, &mark.to_be_bytes())
            }
            Self::Secmark { op, secmark } => push_ct_cmp_from_key(
                exprs,
                nftables::CtKeys::Secmark,
                *op,
                &secmark.to_be_bytes(),
            ),
            Self::Expiration { op, expiration } => push_ct_cmp_from_key(
                exprs,
                nftables::CtKeys::Expiration,
                *op,
                &expiration.to_be_bytes(),
            ),
            Self::L3Protocol { op, l3protocol } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::L3protocol, *op, &[*l3protocol])
            }
            Self::Protocol { op, protocol } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Protocol, *op, &[*protocol])
            }
            Self::ProtoSrc { op, proto_src } => push_ct_cmp_from_key(
                exprs,
                nftables::CtKeys::ProtoSrc,
                *op,
                &proto_src.to_be_bytes(),
            ),
            Self::ProtoDst { op, proto_dst } => push_ct_cmp_from_key(
                exprs,
                nftables::CtKeys::ProtoDst,
                *op,
                &proto_dst.to_be_bytes(),
            ),
            Self::Zone { op, zone } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Zone, *op, &zone.to_be_bytes())
            }
            Self::Helper { op, helper } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Helper, *op, helper.as_bytes())
            }
            Self::Src { op, src } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Src, *op, &src.to_be_bytes())
            }
            Self::Dst { op, dst } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Dst, *op, &dst.to_be_bytes())
            }
            Self::SrcIp { op, addr } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::SrcIp, *op, &addr.octets())
            }
            Self::DstIp { op, addr } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::DstIp, *op, &addr.octets())
            }
            Self::SrcIp6 { op, addr } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::SrcIp6, *op, &addr.octets())
            }
            Self::DstIp6 { op, addr } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::DstIp6, *op, &addr.octets())
            }
            Self::Pkts { op, pkts } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Pkts, *op, &pkts.to_be_bytes())
            }
            Self::Bytes { op, bytes } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Bytes, *op, &bytes.to_be_bytes())
            }
            Self::Avgpkt { op, avgpkt } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::Avgpkt, *op, &avgpkt.to_be_bytes())
            }
            Self::Eventmask { op, eventmask } => push_ct_cmp_from_key(
                exprs,
                nftables::CtKeys::Eventmask,
                *op,
                &eventmask.to_be_bytes(),
            ),
            Self::Id { op, ct_id } => {
                push_ct_cmp_from_key(exprs, nftables::CtKeys::CtId, *op, &ct_id.to_be_bytes())
            }
        }
    }
}
#[repr(u32)]
enum CtStateBit {
    Invalid = 1 << 0,
    Established = 1 << 1,
    Related = 1 << 2,
    New = 1 << 3,
    Untracked = 1 << 6,
}

use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

use super::NftExpression;
use super::shared::{
    parse_cmp_mapped_conditions, parse_eq_neq_mapped_string_conditions, parse_ifname,
    parse_kind_token, parse_nfproto, parse_proto, parse_unsigned_token, push_meta_cmp_from_key,
};

pub(crate) fn parse_meta_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"meta") {
        return None;
    }

    match tokens.get(i + 1) {
        Some(&"l4proto") => {
            parse_cmp_mapped_conditions(tokens, i + 2, end, expansions, parse_proto, |op, proto| {
                NftExpression::Meta(NftMeta::L4Proto { op, proto })
            })
        }
        Some(&"nfproto") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_nfproto,
            |op, nfproto| NftExpression::Meta(NftMeta::NfProto { op, nfproto }),
        ),
        Some(&"mark") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, mark| NftExpression::Meta(NftMeta::Mark { op, mark }),
        ),
        Some(&"skuid") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, uid| NftExpression::Meta(NftMeta::Skuid { op, uid }),
        ),
        Some(&"skgid") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, gid| NftExpression::Meta(NftMeta::Skgid { op, gid }),
        ),
        Some(&"iif") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, ifindex| NftExpression::Meta(NftMeta::Iif { op, ifindex }),
        ),
        Some(&"oif") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, ifindex| NftExpression::Meta(NftMeta::Oif { op, ifindex }),
        ),
        Some(&"iiftype") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::IifType { op, iftype: value }),
        ),
        Some(&"oiftype") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::OifType { op, iftype: value }),
        ),
        Some(&"iifname") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_ifname,
            |op, ifname| NftExpression::Meta(NftMeta::IifName { op, ifname }),
        ),
        Some(&"oifname") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_ifname,
            |op, ifname| NftExpression::Meta(NftMeta::OifName { op, ifname }),
        ),
        Some(&"bri_iifname") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_ifname,
            |op, ifname| NftExpression::Meta(NftMeta::BriIifName { op, ifname }),
        ),
        Some(&"bri_oifname") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_ifname,
            |op, ifname| NftExpression::Meta(NftMeta::BriOifName { op, ifname }),
        ),
        Some(&"secmark") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Secmark { op, secmark: value }),
        ),
        Some(&"priority") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| {
                NftExpression::Meta(NftMeta::Priority {
                    op,
                    priority: value,
                })
            },
        ),
        Some(&"len") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Len { op, len: value }),
        ),
        Some(&"rtclassid") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| {
                NftExpression::Meta(NftMeta::Rtclassid {
                    op,
                    rtclassid: value,
                })
            },
        ),
        Some(&"cpu") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Cpu { op, cpu: value }),
        ),
        Some(&"iifgroup") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Iifgroup { op, group: value }),
        ),
        Some(&"oifgroup") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Oifgroup { op, group: value }),
        ),
        Some(&"nftrace") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Nftrace { op, nftrace: value }),
        ),
        Some(&"cgroup") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Cgroup { op, cgroup: value }),
        ),
        Some(&"prandom") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Prandom { op, prandom: value }),
        ),
        Some(&"secpath") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Secpath { op, secpath: value }),
        ),
        Some(&"pkttype") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Pkttype { op, pkttype: value }),
        ),
        Some(&"sdif") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::Sdif { op, ifindex: value }),
        ),
        Some(&"sdifname") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_ifname,
            |op, ifname| NftExpression::Meta(NftMeta::SdifName { op, ifname }),
        ),
        Some(&"iifkind") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_kind_token,
            |op, kind| NftExpression::Meta(NftMeta::IifKind { op, kind }),
        ),
        Some(&"oifkind") => parse_eq_neq_mapped_string_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_kind_token,
            |op, kind| NftExpression::Meta(NftMeta::OifKind { op, kind }),
        ),
        Some(&"time") => parse_meta_time_conditions(tokens, i, end, expansions),
        Some(&"protocol") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, value| NftExpression::Meta(NftMeta::Protocol { op, value }),
        ),
        Some(&"bri_iifpvid") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, value| NftExpression::Meta(NftMeta::BriIifpvid { op, value }),
        ),
        Some(&"bri_iifvproto") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u16>,
            |op, value| NftExpression::Meta(NftMeta::BriIifvproto { op, value }),
        ),
        Some(&"bri_broute") => parse_cmp_mapped_conditions(
            tokens,
            i + 2,
            end,
            expansions,
            parse_unsigned_token::<u8>,
            |op, value| NftExpression::Meta(NftMeta::BriBroute { op, value }),
        ),
        _ => None,
    }
}

fn parse_meta_time_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    match tokens.get(i + 2) {
        Some(&"ns") => parse_cmp_mapped_conditions(
            tokens,
            i + 3,
            end,
            expansions,
            parse_unsigned_token::<u64>,
            |op, value| NftExpression::Meta(NftMeta::TimeNs { op, value }),
        ),
        Some(&"day") => parse_cmp_mapped_conditions(
            tokens,
            i + 3,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::TimeDay { op, value }),
        ),
        Some(&"hour") => parse_cmp_mapped_conditions(
            tokens,
            i + 3,
            end,
            expansions,
            parse_unsigned_token::<u32>,
            |op, value| NftExpression::Meta(NftMeta::TimeHour { op, value }),
        ),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) enum NftMeta {
    L4Proto {
        op: nftables::CmpOps,
        proto: u8,
    },
    NfProto {
        op: nftables::CmpOps,
        nfproto: u8,
    },
    Mark {
        op: nftables::CmpOps,
        mark: u32,
    },
    Skuid {
        op: nftables::CmpOps,
        uid: u32,
    },
    Skgid {
        op: nftables::CmpOps,
        gid: u32,
    },
    Iif {
        op: nftables::CmpOps,
        ifindex: u32,
    },
    Oif {
        op: nftables::CmpOps,
        ifindex: u32,
    },
    IifType {
        op: nftables::CmpOps,
        iftype: u32,
    },
    OifType {
        op: nftables::CmpOps,
        iftype: u32,
    },
    IifName {
        op: nftables::CmpOps,
        ifname: String,
    },
    OifName {
        op: nftables::CmpOps,
        ifname: String,
    },
    BriIifName {
        op: nftables::CmpOps,
        ifname: String,
    },
    BriOifName {
        op: nftables::CmpOps,
        ifname: String,
    },
    Secmark {
        op: nftables::CmpOps,
        secmark: u32,
    },
    Priority {
        op: nftables::CmpOps,
        priority: u32,
    },
    Len {
        op: nftables::CmpOps,
        len: u32,
    },
    Rtclassid {
        op: nftables::CmpOps,
        rtclassid: u32,
    },
    Cpu {
        op: nftables::CmpOps,
        cpu: u32,
    },
    Iifgroup {
        op: nftables::CmpOps,
        group: u32,
    },
    Oifgroup {
        op: nftables::CmpOps,
        group: u32,
    },
    Nftrace {
        op: nftables::CmpOps,
        nftrace: u32,
    },
    Cgroup {
        op: nftables::CmpOps,
        cgroup: u32,
    },
    Prandom {
        op: nftables::CmpOps,
        prandom: u32,
    },
    Secpath {
        op: nftables::CmpOps,
        secpath: u32,
    },
    Pkttype {
        op: nftables::CmpOps,
        pkttype: u32,
    },
    Sdif {
        op: nftables::CmpOps,
        ifindex: u32,
    },
    SdifName {
        op: nftables::CmpOps,
        ifname: String,
    },
    IifKind {
        op: nftables::CmpOps,
        kind: String,
    },
    OifKind {
        op: nftables::CmpOps,
        kind: String,
    },
    TimeNs {
        op: nftables::CmpOps,
        value: u64,
    },
    TimeDay {
        op: nftables::CmpOps,
        value: u32,
    },
    TimeHour {
        op: nftables::CmpOps,
        value: u32,
    },
    Protocol {
        op: nftables::CmpOps,
        value: u16,
    },
    BriIifpvid {
        op: nftables::CmpOps,
        value: u16,
    },
    BriIifvproto {
        op: nftables::CmpOps,
        value: u16,
    },
    BriBroute {
        op: nftables::CmpOps,
        value: u8,
    },
}

impl NftMeta {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::L4Proto { op, proto } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::L4Proto, *op, &[*proto])
            }
            Self::NfProto { op, nfproto } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Nfproto, *op, &[*nfproto])
            }
            Self::Mark { op, mark } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Mark, *op, &mark.to_be_bytes())
            }
            Self::Skuid { op, uid } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Skuid, *op, &uid.to_be_bytes())
            }
            Self::Skgid { op, gid } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Skgid, *op, &gid.to_be_bytes())
            }
            Self::Iif { op, ifindex } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Iif, *op, &ifindex.to_be_bytes())
            }
            Self::Oif { op, ifindex } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Oif, *op, &ifindex.to_be_bytes())
            }
            Self::IifType { op, iftype } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Iftype,
                *op,
                &iftype.to_be_bytes(),
            ),
            Self::OifType { op, iftype } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Oiftype,
                *op,
                &iftype.to_be_bytes(),
            ),
            Self::IifName { op, ifname } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Iifname, *op, ifname.as_bytes())
            }
            Self::OifName { op, ifname } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Oifname, *op, ifname.as_bytes())
            }
            Self::BriIifName { op, ifname } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::BriIifname,
                *op,
                ifname.as_bytes(),
            ),
            Self::BriOifName { op, ifname } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::BriOifname,
                *op,
                ifname.as_bytes(),
            ),
            Self::Secmark { op, secmark } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Secmark,
                *op,
                &secmark.to_be_bytes(),
            ),
            Self::Priority { op, priority } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Priority,
                *op,
                &priority.to_be_bytes(),
            ),
            Self::Len { op, len } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Len, *op, &len.to_be_bytes())
            }
            Self::Rtclassid { op, rtclassid } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Rtclassid,
                *op,
                &rtclassid.to_be_bytes(),
            ),
            Self::Cpu { op, cpu } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Cpu, *op, &cpu.to_be_bytes())
            }
            Self::Iifgroup { op, group } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Iifgroup,
                *op,
                &group.to_be_bytes(),
            ),
            Self::Oifgroup { op, group } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Oifgroup,
                *op,
                &group.to_be_bytes(),
            ),
            Self::Nftrace { op, nftrace } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Nftrace,
                *op,
                &nftrace.to_be_bytes(),
            ),
            Self::Cgroup { op, cgroup } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Cgroup,
                *op,
                &cgroup.to_be_bytes(),
            ),
            Self::Prandom { op, prandom } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Prandom,
                *op,
                &prandom.to_be_bytes(),
            ),
            Self::Secpath { op, secpath } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Secpath,
                *op,
                &secpath.to_be_bytes(),
            ),
            Self::Pkttype { op, pkttype } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Pkttype,
                *op,
                &pkttype.to_be_bytes(),
            ),
            Self::Sdif { op, ifindex } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Sdif, *op, &ifindex.to_be_bytes())
            }
            Self::SdifName { op, ifname } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Sdifname, *op, ifname.as_bytes())
            }
            Self::IifKind { op, kind } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Iifkind, *op, kind.as_bytes())
            }
            Self::OifKind { op, kind } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::Oifkind, *op, kind.as_bytes())
            }
            Self::TimeNs { op, value } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::TimeNs, *op, &value.to_be_bytes())
            }
            Self::TimeDay { op, value } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::TimeDay,
                *op,
                &value.to_be_bytes(),
            ),
            Self::TimeHour { op, value } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::TimeHour,
                *op,
                &value.to_be_bytes(),
            ),
            Self::Protocol { op, value } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::Protocol,
                *op,
                &value.to_be_bytes(),
            ),
            Self::BriIifpvid { op, value } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::BriIifpvid,
                *op,
                &value.to_be_bytes(),
            ),
            Self::BriIifvproto { op, value } => push_meta_cmp_from_key(
                exprs,
                nftables::MetaKeys::BriIifvproto,
                *op,
                &value.to_be_bytes(),
            ),
            Self::BriBroute { op, value } => {
                push_meta_cmp_from_key(exprs, nftables::MetaKeys::BriBroute, *op, &[*value])
            }
        }
    }
}

use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

use super::NftExpression;
use super::bitwise::NftBitwise;
use super::lookup::NftLookup;
use super::shared::{
    parse_proto, push_cmp_from_reg1, push_condition, push_meta_cmp_from_key, push_payload_cmp,
    push_payload_load_to_reg1, push_payload_range,
};

mod icmp;
mod ip;
mod ip6;
mod transport;

use icmp::parse_icmp_conditions;
use ip::parse_ip_conditions;
use ip6::parse_ip6_conditions;
use transport::{parse_th_conditions, parse_th_like_conditions};

pub(crate) type PayloadParseResult = (Vec<Vec<NftExpression>>, usize);

#[repr(u8)]
enum TcpControlFlag {
    Fin = 0x01,
    Syn = 0x02,
    Rst = 0x04,
    Ack = 0x10,
}

const TCP_FLAG_MASK_FIN_SYN_RST_ACK: u8 = (TcpControlFlag::Fin as u8)
    | (TcpControlFlag::Syn as u8)
    | (TcpControlFlag::Rst as u8)
    | (TcpControlFlag::Ack as u8);
const TCP_FLAG_SYN: u8 = TcpControlFlag::Syn as u8;

pub(crate) fn parse_payload_family(
    tokens: &[&str],
    i: usize,
    end: usize,
    mut expansions: Vec<Vec<NftExpression>>,
) -> Option<PayloadParseResult> {
    match tokens.get(i) {
        Some(&"ip") => parse_ip_conditions(tokens, i, end, expansions),
        Some(&"ip6") => parse_ip6_conditions(tokens, i, end, expansions),
        Some(&"th") if matches!(tokens.get(i + 1), Some(&"dport") | Some(&"sport")) => {
            parse_th_conditions(tokens, i, end, expansions)
        }
        Some(&"tcp") | Some(&"udp")
            if matches!(
                tokens.get(i + 1),
                Some(&"dport") | Some(&"sport") | Some(&"len") | Some(&"length")
            ) =>
        {
            let proto = parse_proto(*tokens.get(i)?)?;
            push_condition(
                &mut expansions,
                NftExpression::Meta(super::meta::NftMeta::L4Proto {
                    op: nftables::CmpOps::Eq,
                    proto,
                }),
            );
            parse_th_like_conditions(tokens, i, end, expansions)
        }
        Some(&"icmp") | Some(&"icmpv6")
            if matches!(
                tokens.get(i + 1),
                Some(&"type") | Some(&"code") | Some(&"checksum")
            ) =>
        {
            parse_icmp_conditions(tokens, i, end, expansions)
        }
        Some(&"tcp")
            if tokens.get(i + 1) == Some(&"flags")
                && tokens.get(i + 2) == Some(&"&")
                && tokens.get(i + 3) == Some(&"(fin|syn|rst|ack)")
                && tokens.get(i + 4) == Some(&"==")
                && tokens.get(i + 5) == Some(&"syn") =>
        {
            push_condition(
                &mut expansions,
                NftExpression::Payload(NftPayload::TcpSynFlags),
            );
            Some((expansions, i + 6))
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) enum NftPayload {
    IpProtocol {
        op: nftables::CmpOps,
        proto: u8,
    },
    IpTtl {
        op: nftables::CmpOps,
        ttl: u8,
    },
    Ip6NextHeader {
        op: nftables::CmpOps,
        proto: u8,
    },
    Ip6HopLimit {
        op: nftables::CmpOps,
        hop_limit: u8,
    },
    Ipv4Addr {
        op: nftables::CmpOps,
        offset: u32,
        addr: std::net::Ipv4Addr,
    },
    Ipv6Addr {
        op: nftables::CmpOps,
        offset: u32,
        addr: std::net::Ipv6Addr,
    },
    Ipv4AddrRange {
        op: nftables::RangeOps,
        offset: u32,
        start: std::net::Ipv4Addr,
        end: std::net::Ipv4Addr,
    },
    Ipv4AddrCidr {
        op: nftables::CmpOps,
        offset: u32,
        mask: u32,
        value: u32,
    },
    Ipv6AddrRange {
        op: nftables::RangeOps,
        offset: u32,
        start: std::net::Ipv6Addr,
        end: std::net::Ipv6Addr,
    },
    Ipv6AddrCidr {
        op: nftables::CmpOps,
        offset: u32,
        mask: [u8; 16],
        value: [u8; 16],
    },
    LookupIpv4Addr {
        offset: u32,
        set: String,
        invert: bool,
    },
    LookupIpv6Addr {
        offset: u32,
        set: String,
        invert: bool,
    },
    LookupTransportPort {
        offset: u32,
        set: String,
        invert: bool,
    },
    TcpSynFlags,
    TransportPort {
        op: nftables::CmpOps,
        offset: u32,
        port: u16,
    },
    TransportPortRange {
        op: nftables::RangeOps,
        offset: u32,
        start: u16,
        end: u16,
    },
    IcmpType {
        proto: u8,
        type_code: u8,
    },
    IcmpCode {
        proto: u8,
        code: u8,
    },
    IcmpChecksum {
        proto: u8,
        checksum: u16,
    },
    UdpLength {
        op: nftables::CmpOps,
        length: u16,
    },
}

impl NftPayload {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        match self {
            Self::IpProtocol { op, proto } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                9,
                1,
                *op,
                &[*proto],
            ),
            Self::IpTtl { op, ttl } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                8,
                1,
                *op,
                &[*ttl],
            ),
            Self::Ip6NextHeader { op, proto } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                6,
                1,
                *op,
                &[*proto],
            ),
            Self::Ip6HopLimit { op, hop_limit } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                7,
                1,
                *op,
                &[*hop_limit],
            ),
            Self::Ipv4Addr { op, offset, addr } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                *offset,
                4,
                *op,
                &addr.octets(),
            ),
            Self::Ipv6Addr { op, offset, addr } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                *offset,
                16,
                *op,
                &addr.octets(),
            ),
            Self::Ipv4AddrRange {
                op,
                offset,
                start,
                end,
            } => push_payload_range(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                *offset,
                4,
                *op,
                &start.octets(),
                &end.octets(),
            ),
            Self::Ipv6AddrRange {
                op,
                offset,
                start,
                end,
            } => push_payload_range(
                exprs,
                nftables::PayloadBase::NetworkHeader as u32,
                *offset,
                16,
                *op,
                &start.octets(),
                &end.octets(),
            ),
            Self::Ipv4AddrCidr {
                op,
                offset,
                mask,
                value,
            } => {
                let exprs = push_payload_load_to_reg1(
                    exprs,
                    nftables::PayloadBase::NetworkHeader as u32,
                    *offset,
                    4,
                );
                let exprs = NftExpression::Bitwise(NftBitwise {
                    sreg: nftables::Registers::Reg1,
                    dreg: nftables::Registers::Reg1,
                    mask: mask.to_be_bytes().to_vec(),
                    xor: 0_u32.to_be_bytes().to_vec(),
                })
                .encode(exprs);
                push_cmp_from_reg1(exprs, *op, &value.to_be_bytes())
            }
            Self::Ipv6AddrCidr {
                op,
                offset,
                mask,
                value,
            } => {
                let exprs = push_payload_load_to_reg1(
                    exprs,
                    nftables::PayloadBase::NetworkHeader as u32,
                    *offset,
                    16,
                );
                let exprs = NftExpression::Bitwise(NftBitwise {
                    sreg: nftables::Registers::Reg1,
                    dreg: nftables::Registers::Reg1,
                    mask: mask.to_vec(),
                    xor: [0_u8; 16].to_vec(),
                })
                .encode(exprs);
                push_cmp_from_reg1(exprs, *op, value)
            }
            Self::LookupIpv4Addr {
                offset,
                set,
                invert,
            } => {
                let exprs = push_payload_load_to_reg1(
                    exprs,
                    nftables::PayloadBase::NetworkHeader as u32,
                    *offset,
                    4,
                );
                NftExpression::Lookup(NftLookup {
                    set: set.clone(),
                    sreg: nftables::Registers::Reg1,
                    dreg: None,
                    invert: *invert,
                })
                .encode(exprs)
            }
            Self::LookupIpv6Addr {
                offset,
                set,
                invert,
            } => {
                let exprs = push_payload_load_to_reg1(
                    exprs,
                    nftables::PayloadBase::NetworkHeader as u32,
                    *offset,
                    16,
                );
                NftExpression::Lookup(NftLookup {
                    set: set.clone(),
                    sreg: nftables::Registers::Reg1,
                    dreg: None,
                    invert: *invert,
                })
                .encode(exprs)
            }
            Self::LookupTransportPort {
                offset,
                set,
                invert,
            } => {
                let exprs = push_payload_load_to_reg1(
                    exprs,
                    nftables::PayloadBase::TransportHeader as u32,
                    *offset,
                    2,
                );
                NftExpression::Lookup(NftLookup {
                    set: set.clone(),
                    sreg: nftables::Registers::Reg1,
                    dreg: None,
                    invert: *invert,
                })
                .encode(exprs)
            }
            Self::TcpSynFlags => {
                let exprs = push_payload_load_to_reg1(
                    exprs,
                    nftables::PayloadBase::TransportHeader as u32,
                    13,
                    1,
                );
                let exprs = NftExpression::Bitwise(NftBitwise {
                    sreg: nftables::Registers::Reg1,
                    dreg: nftables::Registers::Reg1,
                    mask: vec![TCP_FLAG_MASK_FIN_SYN_RST_ACK],
                    xor: vec![0x00],
                })
                .encode(exprs);
                push_cmp_from_reg1(exprs, nftables::CmpOps::Eq, &[TCP_FLAG_SYN])
            }
            Self::TransportPort { op, offset, port } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::TransportHeader as u32,
                *offset,
                2,
                *op,
                &port.to_be_bytes(),
            ),
            Self::TransportPortRange {
                op,
                offset,
                start,
                end,
            } => push_payload_range(
                exprs,
                nftables::PayloadBase::TransportHeader as u32,
                *offset,
                2,
                *op,
                &start.to_be_bytes(),
                &end.to_be_bytes(),
            ),
            Self::IcmpType { proto, type_code } => {
                let exprs = push_meta_cmp_from_key(
                    exprs,
                    nftables::MetaKeys::L4Proto,
                    nftables::CmpOps::Eq,
                    &[*proto],
                );
                push_payload_cmp(
                    exprs,
                    nftables::PayloadBase::TransportHeader as u32,
                    0,
                    1,
                    nftables::CmpOps::Eq,
                    &[*type_code],
                )
            }
            Self::IcmpCode { proto, code } => {
                let exprs = push_meta_cmp_from_key(
                    exprs,
                    nftables::MetaKeys::L4Proto,
                    nftables::CmpOps::Eq,
                    &[*proto],
                );
                push_payload_cmp(
                    exprs,
                    nftables::PayloadBase::TransportHeader as u32,
                    1,
                    1,
                    nftables::CmpOps::Eq,
                    &[*code],
                )
            }
            Self::IcmpChecksum { proto, checksum } => {
                let exprs = push_meta_cmp_from_key(
                    exprs,
                    nftables::MetaKeys::L4Proto,
                    nftables::CmpOps::Eq,
                    &[*proto],
                );
                push_payload_cmp(
                    exprs,
                    nftables::PayloadBase::TransportHeader as u32,
                    2,
                    2,
                    nftables::CmpOps::Eq,
                    &checksum.to_be_bytes(),
                )
            }
            Self::UdpLength { op, length } => push_payload_cmp(
                exprs,
                nftables::PayloadBase::TransportHeader as u32,
                4,
                2,
                *op,
                &length.to_be_bytes(),
            ),
        }
    }
}

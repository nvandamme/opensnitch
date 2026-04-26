use netlink_bindings::nftables;
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};

use super::NftExpression;
use super::shared::{
    parse_cmp_and_value_index, parse_unsigned_token, push_condition,
};
use super::super::{
    NFTA_EXTHDR_DREG, NFTA_EXTHDR_FLAGS, NFTA_EXTHDR_LEN, NFTA_EXTHDR_OFFSET, NFTA_EXTHDR_OP,
    NFTA_EXTHDR_TYPE, NFTA_EXPR_DATA,
};

const NFT_EXTHDR_F_PRESENT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) enum ExthdrOp {
    #[allow(dead_code)]
    Ipv6 = 0,
    TcpOpt = 1,
}

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftExthdr {
    pub(super) dreg: Option<nftables::Registers>,
    pub(super) hdr_type: u8,
    pub(super) offset: u32,
    pub(super) len: u32,
    pub(super) op: ExthdrOp,
    pub(super) flags: u32,
}

struct TcpOptionSpec {
    name: &'static str,
    hdr_type: u8,
    offset: u32,
    len: u32,
}

const TCP_OPTION_SPECS: &[TcpOptionSpec] = &[
    TcpOptionSpec {
        name: "maxseg",
        hdr_type: 2,
        offset: 2,
        len: 2,
    },
    TcpOptionSpec {
        name: "window",
        hdr_type: 3,
        offset: 2,
        len: 1,
    },
    TcpOptionSpec {
        name: "sack-perm",
        hdr_type: 4,
        offset: 2,
        len: 0,
    },
    TcpOptionSpec {
        name: "sack",
        hdr_type: 5,
        offset: 2,
        len: 0,
    },
    TcpOptionSpec {
        name: "timestamp",
        hdr_type: 8,
        offset: 2,
        len: 4,
    },
];

fn find_tcp_option(name: &str) -> Option<&'static TcpOptionSpec> {
    TCP_OPTION_SPECS.iter().find(|spec| spec.name == name)
}

pub(crate) fn parse_exthdr_conditions(
    tokens: &[&str],
    i: usize,
    end: usize,
    mut expansions: Vec<Vec<NftExpression>>,
) -> Option<(Vec<Vec<NftExpression>>, usize)> {
    if tokens.get(i) != Some(&"tcp") || tokens.get(i + 1) != Some(&"option") {
        return None;
    }

    let opt_name = *tokens.get(i + 2)?;
    let spec = find_tcp_option(opt_name)?;

    let mut next = i + 3;

    if tokens.get(next) == Some(&"exists") {
        let exthdr = NftExthdr {
            dreg: None,
            hdr_type: spec.hdr_type,
            offset: spec.offset,
            len: spec.len,
            op: ExthdrOp::TcpOpt,
            flags: NFT_EXTHDR_F_PRESENT,
        };
        push_condition(&mut expansions, NftExpression::Exthdr(exthdr));
        return Some((expansions, next + 1));
    }

    // skip "size" keyword if present
    if tokens.get(next) == Some(&"size") {
        next += 1;
    }

    if spec.len == 0 {
        return None;
    }

    let (op, value_idx) = parse_cmp_and_value_index(tokens, next, end)?;
    let value = parse_unsigned_token::<u32>(*tokens.get(value_idx)?)?;

    let exthdr = NftExthdr {
        dreg: Some(nftables::Registers::Reg1),
        hdr_type: spec.hdr_type,
        offset: spec.offset,
        len: spec.len,
        op: ExthdrOp::TcpOpt,
        flags: 0,
    };

    let value_bytes = match spec.len {
        1 => vec![value as u8],
        2 => (value as u16).to_be_bytes().to_vec(),
        4 => value.to_be_bytes().to_vec(),
        _ => return None,
    };

    push_condition(&mut expansions, NftExpression::Exthdr(exthdr));
    push_condition(
        &mut expansions,
        NftExpression::Cmp(super::cmp::NftCmp {
            sreg: nftables::Registers::Reg1,
            op,
            data: value_bytes,
        }),
    );

    Some((expansions, value_idx + 1))
}

impl NftExthdr {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let mut expr = exprs.nested_elem().push_name_bytes(b"exthdr");
        let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

        if let Some(dreg) = self.dreg {
            push_header(expr.as_rec_mut(), NFTA_EXTHDR_DREG, 4);
            expr.as_rec_mut().extend((dreg as u32).to_be_bytes());
        }

        push_header(expr.as_rec_mut(), NFTA_EXTHDR_TYPE, 1);
        expr.as_rec_mut().extend([self.hdr_type]);

        push_header(expr.as_rec_mut(), NFTA_EXTHDR_OFFSET, 4);
        expr.as_rec_mut().extend(self.offset.to_be_bytes());

        push_header(expr.as_rec_mut(), NFTA_EXTHDR_LEN, 4);
        expr.as_rec_mut().extend(self.len.to_be_bytes());

        push_header(expr.as_rec_mut(), NFTA_EXTHDR_OP, 4);
        expr.as_rec_mut().extend((self.op as u32).to_be_bytes());

        if self.flags != 0 {
            push_header(expr.as_rec_mut(), NFTA_EXTHDR_FLAGS, 4);
            expr.as_rec_mut().extend(self.flags.to_be_bytes());
        }

        finalize_nested_header(expr.as_rec_mut(), data_offset);
        expr.end_nested()
    }
}

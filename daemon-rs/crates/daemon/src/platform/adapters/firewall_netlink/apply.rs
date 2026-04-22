use netlink_bindings::nftables::{self};
use netlink_bindings::utils::{Rec, finalize_nested_header, push_header, push_nested_header};

use super::{
    NFT_QUEUE_FLAG_BYPASS, NFTA_EXPR_DATA, NFTA_QUEUE_FLAGS, NFTA_QUEUE_NUM, NFTA_QUEUE_TOTAL,
    NetfilterTransactionBuilder, ParsedRuleExpression, RuleAction, RuleCondition, RuleVerdict,
};

impl NetfilterTransactionBuilder {
    pub(super) fn add_system_rule(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        expression: &str,
        tag: &str,
    ) -> bool {
        let parsed_rules = match ParsedRuleExpression::parse_all(expression) {
            Some(parsed) => parsed,
            None => return false,
        };

        for parsed in parsed_rules {
            self.add_parsed_rule(family, table, chain, &parsed, tag);
        }

        true
    }

    fn add_parsed_rule(
        &mut self,
        family: &str,
        table: &str,
        chain: &str,
        parsed: &ParsedRuleExpression,
        tag: &str,
    ) {
        let mut h = Self::msg_header(family);
        h.set_res_id(10);
        let mut request = self.inner.request().set_create().op_newrule_do(&h);
        let mut exprs = request
            .encode()
            .push_table_bytes(table.as_bytes())
            .push_chain_bytes(chain.as_bytes())
            .push_userdata(tag.as_bytes())
            .nested_expressions();

        for cond in &parsed.conditions {
            match cond {
                RuleCondition::MetaL4Proto { op, proto } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_meta()
                        .push_key(nftables::MetaKeys::L4Proto as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::MetaMark { op, mark } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_meta()
                        .push_key(nftables::MetaKeys::Mark as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&mark.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::IpProtocol { op, proto } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(9)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ip6NextHeader { op, proto } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(6)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv4Addr { op, offset, addr } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(4)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&addr.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv6Addr { op, offset, addr } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(16)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&addr.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv4AddrRange {
                    op,
                    offset,
                    start,
                    end,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(4)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_range()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_from_data()
                        .push_value(&start.octets())
                        .end_nested()
                        .nested_to_data()
                        .push_value(&end.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv4AddrCidr {
                    op,
                    offset,
                    mask,
                    value,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(4)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(4)
                        .nested_mask()
                        .push_value(&mask.to_be_bytes())
                        .end_nested()
                        .nested_xor()
                        .push_value(&0_u32.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&value.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv6AddrRange {
                    op,
                    offset,
                    start,
                    end,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(16)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_range()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_from_data()
                        .push_value(&start.octets())
                        .end_nested()
                        .nested_to_data()
                        .push_value(&end.octets())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::Ipv6AddrCidr {
                    op,
                    offset,
                    mask,
                    value,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::NetworkHeader as u32)
                        .push_offset(*offset)
                        .push_len(16)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(16)
                        .nested_mask()
                        .push_value(mask)
                        .end_nested()
                        .nested_xor()
                        .push_value(&[0_u8; 16])
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(value)
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::CtStateMask { mask } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_ct()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_key(nftables::CtKeys::State as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(4)
                        .nested_mask()
                        .push_value(&mask.to_be_bytes())
                        .end_nested()
                        .nested_xor()
                        .push_value(&0_u32.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Neq as u32)
                        .nested_data()
                        .push_value(&0_u32.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::TcpSynFlags => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(13)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_bitwise()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_len(1)
                        .nested_mask()
                        .push_value(&[0x17])
                        .end_nested()
                        .nested_xor()
                        .push_value(&[0x00])
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Eq as u32)
                        .nested_data()
                        .push_value(&[0x02])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::TransportPort { op, offset, port } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(*offset)
                        .push_len(2)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_data()
                        .push_value(&port.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::TransportPortRange {
                    op,
                    offset,
                    start,
                    end,
                } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(*offset)
                        .push_len(2)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_range()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(*op as u32)
                        .nested_from_data()
                        .push_value(&start.to_be_bytes())
                        .end_nested()
                        .nested_to_data()
                        .push_value(&end.to_be_bytes())
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
                RuleCondition::IcmpType { proto, type_code } => {
                    exprs = exprs
                        .nested_elem()
                        .nested_data_meta()
                        .push_key(nftables::MetaKeys::L4Proto as u32)
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Eq as u32)
                        .nested_data()
                        .push_value(&[*proto])
                        .end_nested()
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_payload()
                        .push_dreg(nftables::Registers::Reg1 as u32)
                        .push_base(nftables::PayloadBase::TransportHeader as u32)
                        .push_offset(0)
                        .push_len(1)
                        .end_nested()
                        .end_nested();

                    exprs = exprs
                        .nested_elem()
                        .nested_data_cmp()
                        .push_sreg(nftables::Registers::Reg1 as u32)
                        .push_op(nftables::CmpOps::Eq as u32)
                        .nested_data()
                        .push_value(&[*type_code])
                        .end_nested()
                        .end_nested()
                        .end_nested();
                }
            }
        }

        match parsed.action {
            RuleAction::Verdict(verdict) => {
                let verdict = match verdict {
                    RuleVerdict::Accept => nftables::VerdictCode::Accept,
                    RuleVerdict::Drop => nftables::VerdictCode::Drop,
                };
                exprs = exprs
                    .nested_elem()
                    .nested_data_immediate()
                    .push_dreg(nftables::Registers::RegVerdict as u32)
                    .nested_data()
                    .nested_verdict()
                    .push_code(verdict as u32)
                    .end_nested()
                    .end_nested()
                    .end_nested()
                    .end_nested();
            }
            RuleAction::Queue { num, bypass } => {
                exprs = push_queue_expression(exprs, num, bypass);
            }
        }

        let _ = exprs.end_nested();

        self.has_operation = true;
    }
}

fn push_queue_expression<Prev: Rec>(
    exprs: nftables::PushExprListAttrs<Prev>,
    queue_num: u16,
    bypass: bool,
) -> nftables::PushExprListAttrs<Prev> {
    let mut expr = exprs.nested_elem().push_name_bytes(b"queue");
    let data_offset = push_nested_header(expr.as_rec_mut(), NFTA_EXPR_DATA);

    push_header(expr.as_rec_mut(), NFTA_QUEUE_NUM, 2);
    expr.as_rec_mut().extend(queue_num.to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_QUEUE_TOTAL, 2);
    expr.as_rec_mut().extend(1_u16.to_be_bytes());

    push_header(expr.as_rec_mut(), NFTA_QUEUE_FLAGS, 2);
    let flags = if bypass { NFT_QUEUE_FLAG_BYPASS } else { 0 };
    expr.as_rec_mut().extend(flags.to_be_bytes());

    finalize_nested_header(expr.as_rec_mut(), data_offset);
    expr.end_nested()
}

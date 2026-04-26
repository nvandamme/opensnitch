use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

use super::shared::push_range_from_reg1;

#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftRange {
    pub(super) sreg: nftables::Registers,
    pub(super) op: nftables::RangeOps,
    pub(super) from_data: Vec<u8>,
    pub(super) to_data: Vec<u8>,
}

impl NftRange {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        push_range_from_reg1(exprs, self.op, &self.from_data, &self.to_data)
    }
}

use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

/// Standalone comparison expression.
///
/// Compares the value loaded in the source register against `data`
/// using the comparison operator `op`.
#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftCmp {
    pub(super) sreg: nftables::Registers,
    pub(super) op: nftables::CmpOps,
    pub(super) data: Vec<u8>,
}

impl NftCmp {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        exprs
            .nested_elem()
            .nested_data_cmp()
            .push_sreg(self.sreg as u32)
            .push_op(self.op as u32)
            .nested_data()
            .push_value(&self.data)
            .end_nested()
            .end_nested()
            .end_nested()
    }
}

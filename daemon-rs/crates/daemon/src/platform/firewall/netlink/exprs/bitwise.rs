use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

/// Standalone bitwise mask-and-xor expression.
///
/// Applies `(value & mask) ^ xor` on the data in the source register,
/// writing the result to the destination register.
#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftBitwise {
    pub(super) sreg: nftables::Registers,
    pub(super) dreg: nftables::Registers,
    pub(super) mask: Vec<u8>,
    pub(super) xor: Vec<u8>,
}

impl NftBitwise {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        debug_assert_eq!(self.mask.len(), self.xor.len());
        exprs
            .nested_elem()
            .nested_data_bitwise()
            .push_sreg(self.sreg as u32)
            .push_dreg(self.dreg as u32)
            .push_len(self.mask.len() as u32)
            .nested_mask()
            .push_value(&self.mask)
            .end_nested()
            .nested_xor()
            .push_value(&self.xor)
            .end_nested()
            .end_nested()
            .end_nested()
    }
}

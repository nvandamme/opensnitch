use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

/// Standalone immediate expression.
///
/// Loads immediate data into the specified destination register.
/// Verdict immediates are handled separately by `NftVerdict`.
#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftImmediate {
    pub(super) dreg: nftables::Registers,
    pub(super) data: Vec<u8>,
}

impl NftImmediate {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        exprs
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(self.dreg as u32)
            .nested_data()
            .push_value(&self.data)
            .end_nested()
            .end_nested()
            .end_nested()
    }
}

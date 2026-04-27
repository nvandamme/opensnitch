use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

/// Standalone set lookup expression.
///
/// Looks up the value in the source register against a named set.
/// Optionally stores a mapped result into `dreg`.
#[derive(Debug, Clone)]
pub(in crate::platform::firewall::netlink) struct NftLookup {
    pub(super) set: String,
    pub(super) sreg: nftables::Registers,
    pub(super) dreg: Option<nftables::Registers>,
    pub(super) invert: bool,
}

impl NftLookup {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        let flags = if self.invert {
            nftables::LookupFlags::Invert as u32
        } else {
            0
        };

        let mut lookup = exprs
            .nested_elem()
            .nested_data_lookup()
            .push_set_bytes(self.set.as_bytes())
            .push_sreg(self.sreg as u32)
            .push_flags(flags);

        if let Some(dreg) = self.dreg {
            lookup = lookup.push_dreg(dreg as u32);
        }

        lookup.end_nested().end_nested()
    }
}

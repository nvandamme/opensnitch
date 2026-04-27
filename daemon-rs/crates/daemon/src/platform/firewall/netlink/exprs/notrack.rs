use crate::platform::netlink::attrs::NetlinkAttributeRecord;
use netlink_bindings::nftables;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) struct NftNotrack;

impl NftNotrack {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: NetlinkAttributeRecord>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        exprs.nested_elem().push_name_bytes(b"notrack").end_nested()
    }
}

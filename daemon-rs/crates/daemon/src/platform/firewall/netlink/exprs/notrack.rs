use netlink_bindings::nftables;
use netlink_bindings::utils::Rec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::platform::firewall::netlink) struct NftNotrack;

impl NftNotrack {
    pub(in crate::platform::firewall::netlink) fn encode<Prev: Rec>(
        &self,
        exprs: nftables::PushExprListAttrs<Prev>,
    ) -> nftables::PushExprListAttrs<Prev> {
        exprs.nested_elem().push_name_bytes(b"notrack").end_nested()
    }
}

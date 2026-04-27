//! Shared netlink attribute encoding intrinsics.
//!
//! This module gives platform adapters daemon-owned names for the generic
//! attribute-buffer operations supplied by `netlink-bindings`.

use netlink_bindings::utils;

pub(crate) trait NetlinkAttributeRecord: utils::Rec {}

impl<T> NetlinkAttributeRecord for T where T: utils::Rec {}

pub(crate) trait NetlinkAttributeBuffer: NetlinkAttributeRecord {
    fn attrs_mut(&mut self) -> &mut Vec<u8> {
        self.as_rec_mut()
    }
}

impl<T> NetlinkAttributeBuffer for T where T: NetlinkAttributeRecord {}

pub(crate) fn push_nested_attr_header(
    buf: &mut impl NetlinkAttributeRecord,
    attr_type: u16,
) -> usize {
    utils::push_nested_header(buf.as_rec_mut(), attr_type)
}

pub(crate) fn push_attr_header(
    buf: &mut impl NetlinkAttributeRecord,
    attr_type: u16,
    len: u16,
) -> usize {
    utils::push_header(buf.as_rec_mut(), attr_type, len)
}

pub(crate) fn finalize_nested_attr(buf: &mut impl NetlinkAttributeRecord, offset: usize) {
    utils::finalize_nested_header(buf.as_rec_mut(), offset);
}

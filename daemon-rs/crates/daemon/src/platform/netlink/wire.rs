//! Shared low-level netlink wire helpers.
//!
//! These helpers cover generic netlink message/attribute framing only. Protocol
//! adapters remain responsible for protocol-specific attribute IDs and payload
//! schemas.
//!
//! For the consumer-facing trait hierarchy (`NetlinkMessage`, `NetlinkResponse`,
//! `NetlinkEvent`), see [`super::message`].

use netlink_bindings::builtin;
use nix::libc;

use super::message::NetlinkMessage;

pub(crate) const NLMSG_HDR_LEN: usize = builtin::Nlmsghdr::len();
pub(crate) const NLA_HDR_LEN: usize = 4;

/// Internal parsed header used by [`NlmsgIter`] and [`parse_nlmsg_header`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedNlmsgHeader {
    pub(crate) len: usize,
    pub(crate) msg_type: u16,
    pub(crate) flags: u16,
    pub(crate) seq: u32,
}

pub(crate) struct NlmsgIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> NlmsgIter<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for NlmsgIter<'a> {
    type Item = NetlinkMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + NLMSG_HDR_LEN > self.buf.len() {
            return None;
        }
        let hdr = parse_nlmsg_header(self.buf, self.offset)?;
        if hdr.len < NLMSG_HDR_LEN {
            self.offset = self.buf.len();
            return None;
        }

        let msg_end = (self.offset + hdr.len).min(self.buf.len());
        let payload = &self.buf[self.offset + NLMSG_HDR_LEN..msg_end];

        let step = nlmsg_align(hdr.len);
        if step == 0 {
            self.offset = self.buf.len();
            return None;
        }
        self.offset = self.offset.saturating_add(step).min(self.buf.len());
        Some(NetlinkMessage {
            msg_type: hdr.msg_type,
            flags: hdr.flags,
            seq: hdr.seq,
            payload,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NlaRef<'a> {
    pub(crate) attr_type: u16,
    pub(crate) data: &'a [u8],
}

pub(crate) struct NlaIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> NlaIter<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for NlaIter<'a> {
    type Item = NlaRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + NLA_HDR_LEN > self.buf.len() {
            return None;
        }
        let nla_len =
            u16::from_ne_bytes([self.buf[self.offset], self.buf[self.offset + 1]]) as usize;
        if nla_len < NLA_HDR_LEN || self.offset + nla_len > self.buf.len() {
            self.offset = self.buf.len();
            return None;
        }

        let attr_type = u16::from_ne_bytes([self.buf[self.offset + 2], self.buf[self.offset + 3]])
            & libc::NLA_TYPE_MASK as u16;
        let data = &self.buf[self.offset + NLA_HDR_LEN..self.offset + nla_len];

        let step = nla_align(nla_len);
        if step == 0 {
            self.offset = self.buf.len();
        } else {
            self.offset = self.offset.saturating_add(step).min(self.buf.len());
        }

        Some(NlaRef { attr_type, data })
    }
}

#[inline(always)]
pub(crate) fn parse_nlmsg_header(buf: &[u8], offset: usize) -> Option<ParsedNlmsgHeader> {
    if offset + NLMSG_HDR_LEN > buf.len() {
        return None;
    }
    let len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
    let msg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().ok()?);
    let flags = u16::from_ne_bytes(buf[offset + 6..offset + 8].try_into().ok()?);
    let seq = u32::from_ne_bytes(buf[offset + 8..offset + 12].try_into().ok()?);
    Some(ParsedNlmsgHeader {
        len,
        msg_type,
        flags,
        seq,
    })
}

#[inline(always)]
pub(crate) fn read_be_u32(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[inline(always)]
pub(crate) fn read_ne_i32(data: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    Some(i32::from_ne_bytes(bytes))
}

#[inline(always)]
pub(crate) fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[inline(always)]
pub(crate) fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Factory contract for raw netlink message builders.
///
/// Protocol adapters can use the default factory directly or wrap it with
/// protocol-specific extension traits when they need typed attribute helpers.
pub(crate) trait NlMsgFactory {
    type Message;

    fn new_message(
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self::Message;

    fn reuse_message(
        buf: Vec<u8>,
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self::Message;
}

pub(crate) struct DefaultNlMsgFactory;

impl NlMsgFactory for DefaultNlMsgFactory {
    type Message = NlMsgBuf;

    fn new_message(
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self::Message {
        NlMsgBuf::new_with_capacity(msg_type, flags, seq, expected_payload_len)
    }

    fn reuse_message(
        buf: Vec<u8>,
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self::Message {
        NlMsgBuf::reuse(buf, msg_type, flags, seq, expected_payload_len)
    }
}

/// Accumulates a raw netlink message as a byte buffer.
/// Call [`NlMsgBuf::finalize`] to patch `nlmsg_len` and obtain the wire bytes.
pub(crate) struct NlMsgBuf(pub(crate) Vec<u8>);

impl NlMsgBuf {
    /// Begin a new message with reserved capacity for the expected payload.
    pub(crate) fn new_with_capacity(
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self {
        let mut buf = Vec::with_capacity(NLMSG_HDR_LEN + expected_payload_len);
        buf.resize(NLMSG_HDR_LEN, 0u8);
        Self::write_header(&mut buf, msg_type, flags, seq);
        Self(buf)
    }

    /// Reuse an existing buffer for a new message, avoiding allocation when
    /// the buffer already has sufficient capacity.
    pub(crate) fn reuse(
        buf: Vec<u8>,
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self {
        let mut buf = buf;
        buf.clear();
        buf.reserve(NLMSG_HDR_LEN + expected_payload_len);
        buf.resize(NLMSG_HDR_LEN, 0u8);
        Self::write_header(&mut buf, msg_type, flags, seq);
        Self(buf)
    }

    fn write_header(buf: &mut Vec<u8>, msg_type: u16, flags: u16, seq: u32) {
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        // nlmsg_pid = 0  (kernel fills in our portid on receipt)
    }

    /// Begin a new message.  `nlmsg_len` is left as a zero placeholder and
    /// patched by [`NlMsgBuf::finalize`].
    #[cfg(test)]
    pub(crate) fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        Self::new_with_capacity(msg_type, flags, seq, 0)
    }

    /// Append a 4-byte nfnetlink `nfgenmsg` sub-header.
    /// `res_id` is written in network byte order.
    pub(crate) fn nfgenmsg_raw(mut self, family: u8, version: u8, res_id: u16) -> Self {
        self.0.push(family);
        self.0.push(version);
        self.0.extend_from_slice(&res_id.to_be_bytes());
        self
    }

    /// Append an NLA carrying a u32 in network byte order.
    pub(crate) fn nla_u32_be(mut self, attr_type: u16, val: u32) -> Self {
        let nla_len = (NLA_HDR_LEN + 4) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0.extend_from_slice(&attr_type.to_ne_bytes());
        self.0.extend_from_slice(&val.to_be_bytes());
        self
    }

    /// Append an NLA with an arbitrary byte payload; pads data to 4-byte alignment.
    pub(crate) fn nla_bytes(mut self, attr_type: u16, data: &[u8]) -> Self {
        let nla_len = (NLA_HDR_LEN + data.len()) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0.extend_from_slice(&attr_type.to_ne_bytes());
        self.0.extend_from_slice(data);
        let pad = nla_align(data.len()) - data.len();
        self.0.extend(std::iter::repeat_n(0u8, pad));
        self
    }

    /// Patch `nlmsg_len` in-place and return the completed wire buffer.
    pub(crate) fn finalize(mut self) -> Vec<u8> {
        let len = self.0.len() as u32;
        self.0[0..4].copy_from_slice(&len.to_ne_bytes());
        self.0
    }

    /// Patch `nlmsg_len` in-place, send through the provided closure, then
    /// return the buffer for reuse.
    pub(crate) fn finalize_send_reuse(
        mut self,
        send_fn: impl FnOnce(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<Vec<u8>> {
        let len = self.0.len() as u32;
        self.0[0..4].copy_from_slice(&len.to_ne_bytes());
        send_fn(&self.0)?;
        Ok(self.0)
    }
}

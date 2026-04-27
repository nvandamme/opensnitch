//! Adapter-local NFQUEUE netlink wire helpers.
//!
//! NOTE(netlink-baseline): these helpers isolate the remaining manual NFQUEUE
//! frame/attribute codec because `netlink-bindings` does not yet expose a
//! complete typed NFQUEUE config/verdict request builder or runtime `NFQA_*`
//! packet attribute iterator for this workload.

use netlink_bindings::nftables;
use nix::libc;

use crate::platform::netlink::message::{NetlinkMessage, NetlinkResponse};
#[cfg(test)]
pub(crate) use crate::platform::netlink::wire::nlmsg_align;
pub(crate) use crate::platform::netlink::wire::{
    DefaultNlMsgFactory, NLA_HDR_LEN, NLMSG_HDR_LEN, NlMsgBuf, NlMsgFactory, NlmsgIter, nla_align,
    read_ne_i32,
};
use crate::platform::netlink::wire::{NlaIter, read_be_u32};

pub(crate) const NFGENMSG_LEN: usize = nftables::Nfgenmsg::len();

pub(crate) trait NfqueueNlMsgExt {
    fn nfgenmsg(self, family: u8, res_id: u16) -> Self;
    /// Append `NFQA_CFG_CMD` payload directly from scalar fields without an
    /// intermediate stack buffer.
    fn nla_cfg_cmd(self, cmd: u8, pf: u16) -> Self;
    /// Append `NFQA_CFG_PARAMS` payload directly from scalar fields without an
    /// intermediate stack buffer.
    fn nla_cfg_params(self, copy_range: u32, copy_mode: u8) -> Self;
    /// Append `NFQA_VERDICT_HDR` payload directly from scalar fields without an
    /// intermediate stack buffer.
    fn nla_verdict_hdr(self, verdict: u32, packet_id: u32) -> Self;
}

impl NfqueueNlMsgExt for NlMsgBuf {
    fn nfgenmsg(self, family: u8, res_id: u16) -> Self {
        self.nfgenmsg_raw(family, libc::NFNETLINK_V0 as u8, res_id)
    }

    fn nla_cfg_cmd(mut self, cmd: u8, pf: u16) -> Self {
        let nla_len = (NLA_HDR_LEN + 4) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0
            .extend_from_slice(&(libc::NFQA_CFG_CMD as u16).to_ne_bytes());
        self.0.push(cmd);
        self.0.push(0);
        self.0.extend_from_slice(&pf.to_be_bytes());
        self
    }

    fn nla_cfg_params(mut self, copy_range: u32, copy_mode: u8) -> Self {
        let nla_len = (NLA_HDR_LEN + 5) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0
            .extend_from_slice(&(libc::NFQA_CFG_PARAMS as u16).to_ne_bytes());
        self.0.extend_from_slice(&copy_range.to_be_bytes());
        self.0.push(copy_mode);
        self.0.extend(std::iter::repeat_n(0u8, nla_align(5) - 5));
        self
    }

    fn nla_verdict_hdr(mut self, verdict: u32, packet_id: u32) -> Self {
        let nla_len = (NLA_HDR_LEN + 8) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0
            .extend_from_slice(&(libc::NFQA_VERDICT_HDR as u16).to_ne_bytes());
        self.0.extend_from_slice(&verdict.to_be_bytes());
        self.0.extend_from_slice(&packet_id.to_be_bytes());
        self
    }
}

/// Fields extracted from one `NFQNL_MSG_PACKET` netlink message.
pub(crate) struct NfqPacket<'a> {
    pub(crate) packet_id: u32,
    pub(crate) payload: &'a [u8],
    pub(crate) uid: u32,
    pub(crate) mark: u32,
    pub(crate) iface_in_idx: u32,
    pub(crate) iface_out_idx: u32,
}

impl<'buf> NetlinkResponse<'buf> for NfqPacket<'buf> {
    fn decode(msg: &NetlinkMessage<'buf>) -> Option<Self> {
        parse_nfq_packet(msg.payload)
    }
}

/// Parse the body of a `NFQNL_MSG_PACKET` message (everything after the
/// `nlmsghdr`). Returns `None` when the mandatory `NFQA_PACKET_HDR` attribute
/// is absent or malformed.
pub(crate) fn parse_nfq_packet(body: &[u8]) -> Option<NfqPacket<'_>> {
    // body = nfgenmsg (4 bytes) + NLA chain
    if body.len() < NFGENMSG_LEN {
        return None;
    }

    let mut packet_id: Option<u32> = None;
    let mut payload: &[u8] = &[];
    let mut uid = 0u32;
    let mut mark = 0u32;
    let mut iface_in_idx = 0u32;
    let mut iface_out_idx = 0u32;

    for nla in NlaIter::new(&body[NFGENMSG_LEN..]) {
        match nla.attr_type {
            x if x == libc::NFQA_PACKET_HDR as u16 => {
                // nfqnl_msg_packet_hdr: packet_id (u32 BE), hw_protocol (u16 BE), hook (u8)
                if nla.data.len() >= 4 {
                    packet_id = read_be_u32(nla.data);
                }
            }
            x if x == libc::NFQA_MARK as u16 => {
                if let Some(value) = read_be_u32(nla.data) {
                    mark = value;
                }
            }
            x if x == libc::NFQA_IFINDEX_INDEV as u16 => {
                if let Some(value) = read_be_u32(nla.data) {
                    iface_in_idx = value;
                }
            }
            x if x == libc::NFQA_IFINDEX_OUTDEV as u16 => {
                if let Some(value) = read_be_u32(nla.data) {
                    iface_out_idx = value;
                }
            }
            x if x == libc::NFQA_PAYLOAD as u16 => {
                payload = nla.data;
            }
            x if x == libc::NFQA_UID as u16 => {
                if let Some(value) = read_be_u32(nla.data) {
                    uid = value;
                }
            }
            _ => {}
        }
    }

    Some(NfqPacket {
        packet_id: packet_id?,
        payload,
        uid,
        mark,
        iface_in_idx,
        iface_out_idx,
    })
}

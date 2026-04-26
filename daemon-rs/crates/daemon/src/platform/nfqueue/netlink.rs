//! Pure-Rust `NETLINK_NETFILTER` backend for NFQUEUE.
//!
//! Replaces the `libnetfilter_queue` C library calls in `platform::nfqueue::ffi` with
//! direct netlink socket I/O.  All packet-parsing, verdict-engine, decision-state, and
//! metrics logic is reused from that module without modification.
//!
//! Canonical NFQUEUE backend using `NETLINK_NETFILTER`.

use std::{
    mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use netlink_bindings::{builtin, nftables};
use nix::libc;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{RecvFlags, SendFlags, recv, send},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::platform::nfqueue::ffi::lifecycle::NfqueueFfiAdapter;
use crate::platform::nfqueue::metrics::NfqueueMetricsState;
use crate::platform::nfqueue::verdict::{NfqueueVerdictEngine, PacketVerdict};

// ─── Protocol constants ───────────────────────────────────────────────────────

// NFQUEUE netlink message types  (subsys << 8 | local_type)
const NFQNL_MSG_PACKET: u16 =
    ((libc::NFNL_SUBSYS_QUEUE as u16) << 8) | (libc::NFQNL_MSG_PACKET as u16);
const NFQNL_MSG_VERDICT: u16 =
    ((libc::NFNL_SUBSYS_QUEUE as u16) << 8) | (libc::NFQNL_MSG_VERDICT as u16);
const NFQNL_MSG_CONFIG: u16 =
    ((libc::NFNL_SUBSYS_QUEUE as u16) << 8) | (libc::NFQNL_MSG_CONFIG as u16);

// Fixed header sizes (bytes).
pub(crate) const NLMSG_HDR_LEN: usize = builtin::Nlmsghdr::len();
pub(crate) const NFGENMSG_LEN: usize = nftables::Nfgenmsg::len();
pub(crate) const NLA_HDR_LEN: usize = 4;

// Queue/socket tuning defaults  (matching `platform::nfqueue::ffi`).
const DEFAULT_PACKET_SIZE: u32 = 4096;
const DEFAULT_QUEUE_SIZE: u32 = 4096;
const DEFAULT_SOCKET_RCVBUF_BYTES: i32 = 8 * 1024 * 1024;
const RECV_BUF_LEN: usize = (DEFAULT_PACKET_SIZE * 2) as usize;
const ACK_RECV_BUF_LEN: usize = 512;

/// Pre-computed verdict message capacity: nlmsg_hdr + nfgenmsg + verdict_hdr NLA + mark NLA.
const VERDICT_BUF_CAPACITY: usize =
    NLMSG_HDR_LEN + NFGENMSG_LEN + (NLA_HDR_LEN + 8) + (NLA_HDR_LEN + 4);

struct ParsedNlmsgHeader {
    len: usize,
    msg_type: u16,
    seq: u32,
}

struct NlmsgRef<'a> {
    hdr: ParsedNlmsgHeader,
    body: &'a [u8],
}

struct NlmsgIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> NlmsgIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for NlmsgIter<'a> {
    type Item = NlmsgRef<'a>;

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
        let body = &self.buf[self.offset + NLMSG_HDR_LEN..msg_end];

        let step = nlmsg_align(hdr.len);
        if step == 0 {
            self.offset = self.buf.len();
            return None;
        }
        self.offset = self.offset.saturating_add(step).min(self.buf.len());
        Some(NlmsgRef { hdr, body })
    }
}

struct NlaRef<'a> {
    attr_type: u16,
    data: &'a [u8],
}

struct NlaIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> NlaIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
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
fn parse_nlmsg_header(buf: &[u8], offset: usize) -> Option<ParsedNlmsgHeader> {
    if offset + NLMSG_HDR_LEN > buf.len() {
        return None;
    }
    let len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
    let msg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().ok()?);
    let seq = u32::from_ne_bytes(buf[offset + 8..offset + 12].try_into().ok()?);
    Some(ParsedNlmsgHeader { len, msg_type, seq })
}

#[inline(always)]
fn read_be_u32(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

#[inline(always)]
fn read_ne_i32(data: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    Some(i32::from_ne_bytes(bytes))
}

// ─── Alignment helpers ────────────────────────────────────────────────────────

#[inline(always)]
pub(crate) fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

#[inline(always)]
pub(crate) fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

// ─── Netlink message builder ──────────────────────────────────────────────────

/// Accumulates a netlink message as a byte buffer.
/// Call [`NlMsg::finalize`] to patch `nlmsg_len` and obtain the wire bytes.
///
/// NOTE(netlink-baseline): this remains manual because `netlink-bindings` does
/// not yet expose a complete NFQUEUE config/verdict request builder surface
/// covering the exact queue lifecycle used here (bind/unbind PF + queue bind +
/// copy mode/range + queue flags/maxlen + verdicts).
pub(crate) struct NlMsg(Vec<u8>);

impl NlMsg {
    /// Begin a new message with reserved capacity for the expected payload.
    pub(crate) fn new_with_capacity(
        msg_type: u16,
        flags: u16,
        seq: u32,
        expected_payload_len: usize,
    ) -> Self {
        let mut buf = Vec::with_capacity(NLMSG_HDR_LEN + expected_payload_len);
        buf.resize(NLMSG_HDR_LEN, 0u8); // nlmsg_len placeholder + zeros
        Self::write_header(&mut buf, msg_type, flags, seq);
        Self(buf)
    }

    /// Reuse an existing buffer for a new message, avoiding allocation when
    /// the buffer already has sufficient capacity.  This is the hot-path
    /// entrypoint for per-packet verdict messages.
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
    /// patched by [`NlMsg::finalize`].
    #[cfg(test)]
    pub(crate) fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        Self::new_with_capacity(msg_type, flags, seq, 0)
    }

    /// Append a 4-byte `nfgenmsg` sub-header.
    /// `res_id` (typically queue number) is written in network byte order.
    pub(crate) fn nfgenmsg(mut self, family: u8, res_id: u16) -> Self {
        self.0.push(family);
        self.0.push(libc::NFNETLINK_V0 as u8);
        self.0.extend_from_slice(&res_id.to_be_bytes()); // __be16
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

    /// Append `NFQA_CFG_CMD` payload directly from scalar fields without an
    /// intermediate stack buffer.
    pub(crate) fn nla_cfg_cmd(mut self, cmd: u8, pf: u16) -> Self {
        let nla_len = (NLA_HDR_LEN + 4) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0
            .extend_from_slice(&(libc::NFQA_CFG_CMD as u16).to_ne_bytes());
        self.0.push(cmd);
        self.0.push(0);
        self.0.extend_from_slice(&pf.to_be_bytes());
        self
    }

    /// Append `NFQA_CFG_PARAMS` payload directly from scalar fields without an
    /// intermediate stack buffer.
    pub(crate) fn nla_cfg_params(mut self, copy_range: u32, copy_mode: u8) -> Self {
        let nla_len = (NLA_HDR_LEN + 5) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0
            .extend_from_slice(&(libc::NFQA_CFG_PARAMS as u16).to_ne_bytes());
        self.0.extend_from_slice(&copy_range.to_be_bytes());
        self.0.push(copy_mode);
        self.0.extend(std::iter::repeat_n(0u8, nla_align(5) - 5));
        self
    }

    /// Append `NFQA_VERDICT_HDR` payload directly from scalar fields without an
    /// intermediate stack buffer.
    pub(crate) fn nla_verdict_hdr(mut self, verdict: u32, packet_id: u32) -> Self {
        let nla_len = (NLA_HDR_LEN + 8) as u16;
        self.0.extend_from_slice(&nla_len.to_ne_bytes());
        self.0
            .extend_from_slice(&(libc::NFQA_VERDICT_HDR as u16).to_ne_bytes());
        self.0.extend_from_slice(&verdict.to_be_bytes());
        self.0.extend_from_slice(&packet_id.to_be_bytes());
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
    /// return the buffer for reuse.  Avoids the ownership transfer of
    /// [`finalize`] so the caller can reclaim the allocation.
    pub(crate) fn finalize_send_reuse(
        mut self,
        send_fn: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let len = self.0.len() as u32;
        self.0[0..4].copy_from_slice(&len.to_ne_bytes());
        send_fn(&self.0)?;
        Ok(self.0)
    }
}

// ─── Incoming packet parser ───────────────────────────────────────────────────

/// Fields extracted from one `NFQNL_MSG_PACKET` netlink message.
pub(crate) struct NfqPacket<'a> {
    pub(crate) packet_id: u32,
    pub(crate) payload: &'a [u8],
    pub(crate) uid: u32,
    pub(crate) mark: u32,
    pub(crate) iface_in_idx: u32,
    pub(crate) iface_out_idx: u32,
}

/// Parse the body of a `NFQNL_MSG_PACKET` message (everything after the 16-byte
/// `nlmsghdr`).  Returns `None` when the mandatory `NFQA_PACKET_HDR` attribute
/// is absent or malformed.
///
/// NOTE(netlink-baseline): kept as explicit attribute walking because the
/// generated bindings currently do not provide a stable typed iterator for the
/// runtime `NFQA_*` packet attribute stream consumed in the hot receive loop.
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

// ─── Socket lifecycle ─────────────────────────────────────────────────────────

struct NfqueueNetlinkSocket {
    fd: OwnedFd,
    queue_num: u16,
    seq: AtomicU32,
}

impl NfqueueNetlinkSocket {
    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Open a `NETLINK_NETFILTER` socket, bind it to the kernel, tune socket
    /// options, and send the full queue-configuration message sequence.
    ///
    /// NOTE(netlink-baseline): raw socket syscalls are retained here because
    /// this path needs fine-grained fd-level tuning (`SO_RCVBUF`,
    /// `NETLINK_NO_ENOBUFS`) and tight poll/recv loop control that is not yet
    /// fully covered by higher-level helpers for this NFQUEUE workload.
    fn open(queue_num: u16) -> Result<Self> {
        // SAFETY: standard libc socket/bind syscalls with checked return values.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw_fd < 0 {
            bail!(
                "socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // SAFETY: sockaddr_nl is a plain C struct; zero-initialising satisfies all
        // alignment requirements, and we overwrite the meaningful fields below.
        let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // nl_pid = 0 → kernel assigns our netlink portid
        // nl_groups = 0 → no multicast group subscription
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            bail!(
                "bind(AF_NETLINK) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        Self::tune_socket(fd.as_raw_fd());

        let s = Self {
            fd,
            queue_num,
            seq: AtomicU32::new(1),
        };
        s.configure_queue()
            .with_context(|| format!("nfqueue netlink queue {} configuration failed", queue_num))?;
        Ok(s)
    }

    fn tune_socket(raw_fd: libc::c_int) {
        let size: libc::c_int = DEFAULT_SOCKET_RCVBUF_BYTES;
        // SAFETY: setsockopt called with correct type + size for each option.
        let rc = unsafe {
            libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            debug!(
                err = %std::io::Error::last_os_error(),
                "nfqueue netlink: SO_RCVBUF tuning failed"
            );
        }

        let one: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                raw_fd,
                libc::SOL_NETLINK,
                libc::NETLINK_NO_ENOBUFS,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            debug!(
                err = %std::io::Error::last_os_error(),
                "nfqueue netlink: NETLINK_NO_ENOBUFS not applied"
            );
        }
    }

    fn configure_queue(&self) -> Result<()> {
        // PF_BIND: subscribe to AF_INET and AF_INET6 packet families (best-effort;
        // modern kernels treat these as no-ops).
        self.send_config_cmd(
            0,
            libc::NFQNL_CFG_CMD_PF_BIND as u8,
            libc::AF_INET as u16,
            false,
        )?;
        self.send_config_cmd(
            0,
            libc::NFQNL_CFG_CMD_PF_BIND as u8,
            libc::AF_INET6 as u16,
            false,
        )?;

        // BIND: attach to the specific queue number; request ACK to surface EBUSY early.
        self.send_config_cmd(self.queue_num, libc::NFQNL_CFG_CMD_BIND as u8, 0, true)
            .with_context(|| format!("BIND to queue {} rejected by kernel", self.queue_num))?;

        // COPY_PACKET mode with copy range = DEFAULT_PACKET_SIZE.
        self.send_config_params(
            self.queue_num,
            DEFAULT_PACKET_SIZE,
            libc::NFQNL_COPY_PACKET as u8,
        )?;

        // Queue depth limit.
        self.send_config_maxlen(self.queue_num, DEFAULT_QUEUE_SIZE)?;

        // UID/GID metadata flags – best-effort, older kernels may lack support.
        if let Err(err) = self.send_config_flags(
            self.queue_num,
            libc::NFQA_CFG_F_UID_GID as u32,
            libc::NFQA_CFG_F_UID_GID as u32,
        ) {
            debug!(
                detail = %err,
                "nfqueue netlink: uid/gid metadata flags unavailable; continuing without uid/gid"
            );
        }

        Ok(())
    }

    // ── Config message senders ──────────────────────────────────────────────

    fn send_config_cmd(&self, queue_num: u16, cmd: u8, pf: u16, request_ack: bool) -> Result<()> {
        let flags = if request_ack {
            (libc::NLM_F_REQUEST as u16) | (libc::NLM_F_ACK as u16)
        } else {
            libc::NLM_F_REQUEST as u16
        };
        let seq = self.next_seq();
        let msg =
            NlMsg::new_with_capacity(NFQNL_MSG_CONFIG, flags, seq, NFGENMSG_LEN + NLA_HDR_LEN + 4)
                .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
                .nla_cfg_cmd(cmd, pf)
                .finalize();
        self.send_raw(&msg)?;
        if request_ack {
            self.recv_ack(seq)?;
        }
        Ok(())
    }

    fn send_config_params(&self, queue_num: u16, copy_range: u32, copy_mode: u8) -> Result<()> {
        let seq = self.next_seq();
        let msg = NlMsg::new_with_capacity(
            NFQNL_MSG_CONFIG,
            libc::NLM_F_REQUEST as u16,
            seq,
            NFGENMSG_LEN + NLA_HDR_LEN + nla_align(5),
        )
        .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
        .nla_cfg_params(copy_range, copy_mode)
        .finalize();
        self.send_raw(&msg)
    }

    fn send_config_maxlen(&self, queue_num: u16, max_len: u32) -> Result<()> {
        let seq = self.next_seq();
        let msg = NlMsg::new_with_capacity(
            NFQNL_MSG_CONFIG,
            libc::NLM_F_REQUEST as u16,
            seq,
            NFGENMSG_LEN + NLA_HDR_LEN + 4,
        )
        .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
        .nla_u32_be(libc::NFQA_CFG_QUEUE_MAXLEN as u16, max_len)
        .finalize();
        self.send_raw(&msg)
    }

    fn send_config_flags(&self, queue_num: u16, mask: u32, flags: u32) -> Result<()> {
        let seq = self.next_seq();
        let msg = NlMsg::new_with_capacity(
            NFQNL_MSG_CONFIG,
            (libc::NLM_F_REQUEST as u16) | (libc::NLM_F_ACK as u16),
            seq,
            NFGENMSG_LEN + 2 * (NLA_HDR_LEN + 4),
        )
        .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
        .nla_u32_be(libc::NFQA_CFG_MASK as u16, mask)
        .nla_u32_be(libc::NFQA_CFG_FLAGS as u16, flags)
        .finalize();
        self.send_raw(&msg)?;
        self.recv_ack(seq)
    }

    // ── Verdict sender ──────────────────────────────────────────────────────

    /// Send a verdict for a packet, reusing `verdict_buf` to avoid per-packet
    /// allocation.  Returns the buffer (possibly grown) for the next call.
    fn send_verdict_reuse(
        &self,
        packet_id: u32,
        verdict: &PacketVerdict,
        verdict_buf: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (v, vmark) = NfqueueVerdictEngine::packet_verdict_to_c(verdict);
        let seq = self.next_seq();
        let payload = NfqueueVerdictEngine::packet_verdict_payload(verdict);
        let expected_len = NFGENMSG_LEN
            + (NLA_HDR_LEN + 8) // NFQA_VERDICT_HDR
            + if vmark != 0 { NLA_HDR_LEN + 4 } else { 0 }
            + payload.map_or(0, |pkt| NLA_HDR_LEN + nla_align(pkt.len()));

        let mut msg = NlMsg::reuse(
            verdict_buf,
            NFQNL_MSG_VERDICT,
            libc::NLM_F_REQUEST as u16,
            seq,
            expected_len,
        )
        .nfgenmsg(libc::AF_UNSPEC as u8, self.queue_num)
        .nla_verdict_hdr(v, packet_id);

        if vmark != 0 {
            msg = msg.nla_u32_be(libc::NFQA_MARK as u16, vmark);
        }
        if let Some(pkt) = payload {
            msg = msg.nla_bytes(libc::NFQA_PAYLOAD as u16, pkt);
        }

        msg.finalize_send_reuse(|buf| self.send_raw(buf))
    }

    // ── Socket I/O ──────────────────────────────────────────────────────────

    fn send_raw(&self, buf: &[u8]) -> Result<()> {
        let sent = send(self.fd.as_fd(), buf, SendFlags::empty())
            .map_err(|e| anyhow::anyhow!("netlink send failed: {e}"))?;
        if sent != buf.len() {
            bail!(
                "netlink send short write: sent {} of {} bytes",
                sent,
                buf.len()
            );
        }
        Ok(())
    }

    /// Read one netlink reply and check whether it is an ACK for `expected_seq`.
    ///
    /// Tolerates interleaved `NFQNL_MSG_PACKET` messages (they are skipped) so
    /// this can be called safely during the brief configuration window before
    /// netfilter intercept rules become active.
    fn recv_ack(&self, expected_seq: u32) -> Result<()> {
        let mut buf = [0u8; ACK_RECV_BUF_LEN];
        let deadline = Instant::now() + Duration::from_millis(500);

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("nfqueue netlink ack timeout (seq={})", expected_seq);
            }
            // SAFETY: self.fd is valid for the duration of recv_ack.
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) };
            let timeout = Timespec::try_from(remaining).ok();
            let mut pfd = [PollFd::new(&borrowed_fd, PollFlags::IN)];
            if poll(&mut pfd, timeout.as_ref()).context("poll nfqueue ack")? == 0 {
                bail!("nfqueue netlink ack timeout (seq={})", expected_seq);
            }
            let recv_rc = match recv(borrowed_fd, &mut buf, RecvFlags::DONTWAIT) {
                Ok((n, _)) => n,
                Err(e) if e == Errno::AGAIN || e == Errno::WOULDBLOCK => continue,
                Err(e) => bail!("nfqueue netlink ack recv: {}", e),
            };
            if recv_rc < NLMSG_HDR_LEN {
                continue;
            }

            let received = &buf[..recv_rc];
            for msg in NlmsgIter::new(received) {
                if msg.hdr.msg_type == libc::NLMSG_ERROR as u16 && msg.hdr.seq == expected_seq {
                    // nlmsgerr.error is a negative errno (i32 LE) at offset 16.
                    if let Some(errno) = read_ne_i32(msg.body) {
                        if errno == 0 {
                            return Ok(()); // ACK = success
                        }
                        bail!(
                            "nfqueue netlink config error (seq={}, errno={})",
                            expected_seq,
                            errno.unsigned_abs()
                        );
                    }
                    return Ok(());
                }
            }
            // Skip non-matching sequence and non-error messages (e.g. packets racing in).
        }
    }

    // ── Main recv loop ──────────────────────────────────────────────────────

    fn run(self, shutdown: CancellationToken) -> Result<()> {
        let mut buf = [0u8; RECV_BUF_LEN];
        // Pre-allocate a verdict buffer that is reused across iterations,
        // avoiding per-packet Vec allocation in the hot loop.
        let mut verdict_buf = Vec::with_capacity(VERDICT_BUF_CAPACITY);
        let mut last_metrics_log = Instant::now();
        // SAFETY: self.fd remains valid until the loop exits.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) };
        let timeout = Timespec::try_from(Duration::from_millis(500)).ok();

        debug!(
            queue_num = self.queue_num,
            backend = "netlink",
            "nfqueue netlink backend started"
        );

        while !shutdown.is_cancelled() {
            Self::maybe_log_metrics(self.queue_num, &mut last_metrics_log);

            let mut pfd = [PollFd::new(&borrowed_fd, PollFlags::IN)];
            if poll(&mut pfd, timeout.as_ref()).context("poll nfqueue netlink fd")? == 0 {
                continue;
            }
            if !pfd[0].revents().contains(PollFlags::IN) {
                continue;
            }

            let recv_rc = match recv(borrowed_fd, &mut buf, RecvFlags::DONTWAIT) {
                Ok((n, _)) => n,
                Err(e) if e == Errno::WOULDBLOCK || e == Errno::AGAIN => continue,
                Err(e) => {
                    NfqueueMetricsState::record_recv_error(self.queue_num);
                    if e == Errno::NOBUFS {
                        debug!("nfqueue netlink recv overflow (ENOBUFS)");
                    } else {
                        warn!(err = %e, "nfqueue netlink recv failed");
                    }
                    continue;
                }
            };
            if recv_rc == 0 {
                NfqueueMetricsState::record_recv_error(self.queue_num);
                warn!("nfqueue netlink recv returned EOF");
                continue;
            }

            let received = &buf[..recv_rc];
            for msg in NlmsgIter::new(received) {
                match msg.hdr.msg_type {
                    NFQNL_MSG_PACKET => {
                        if let Some(pkt) = parse_nfq_packet(msg.body) {
                            let verdict = NfqueueVerdictEngine::compute_packet_verdict(
                                self.queue_num,
                                pkt.packet_id,
                                pkt.payload,
                                pkt.uid,
                                pkt.mark,
                                pkt.iface_in_idx,
                                pkt.iface_out_idx,
                            );
                            NfqueueMetricsState::record_packet_verdict(self.queue_num, &verdict);
                            match self.send_verdict_reuse(pkt.packet_id, &verdict, verdict_buf) {
                                Ok(returned_buf) => verdict_buf = returned_buf,
                                Err(err) => {
                                    // Buffer is lost on error; re-allocate for next iteration.
                                    verdict_buf = Vec::with_capacity(VERDICT_BUF_CAPACITY);
                                    warn!(detail = %err, "nfqueue netlink: verdict send failed");
                                }
                            }
                        } else {
                            NfqueueMetricsState::record_recv_error(self.queue_num);
                            debug!(
                                "nfqueue netlink: malformed NFQNL_MSG_PACKET (missing packet_id)"
                            );
                        }
                    }
                    x if x == libc::NLMSG_ERROR as u16 => {
                        if let Some(errno) = read_ne_i32(msg.body) {
                            if errno != 0 {
                                debug!(errno, "nfqueue netlink error message in recv loop");
                            }
                        }
                    }
                    x if x == libc::NLMSG_DONE as u16 => break,
                    _ => {}
                }
            }
        }

        debug!(
            queue_num = self.queue_num,
            "nfqueue netlink backend stopped"
        );
        Ok(())
    }

    fn maybe_log_metrics(queue_num: u16, last_log: &mut Instant) {
        if last_log.elapsed() < Duration::from_secs(60) {
            return;
        }
        *last_log = Instant::now();
        debug!(queue_num, "nfqueue netlink queue active");
    }
}

impl Drop for NfqueueNetlinkSocket {
    fn drop(&mut self) {
        // Send UNBIND so the kernel releases the queue slot.  Best-effort.
        let seq = self.next_seq();
        let msg = NlMsg::new_with_capacity(
            NFQNL_MSG_CONFIG,
            libc::NLM_F_REQUEST as u16,
            seq,
            NFGENMSG_LEN + NLA_HDR_LEN + 4,
        )
        .nfgenmsg(libc::AF_UNSPEC as u8, self.queue_num)
        .nla_cfg_cmd(libc::NFQNL_CFG_CMD_UNBIND as u8, 0)
        .finalize();
        let _ = self.send_raw(&msg);
    }
}

// ─── Public adapter surface ───────────────────────────────────────────────────

/// `NETLINK_NETFILTER` NFQUEUE backend.
pub(crate) struct NfqueueNetlinkAdapter;

impl NfqueueNetlinkAdapter {
    /// Run the NFQUEUE recv/verdict loop for `queue_num` until `shutdown` is cancelled.
    ///
    /// `NfqueueRuntimeState::init` must be called before this method.
    pub(crate) fn run(queue_num: u16, shutdown: CancellationToken) -> Result<()> {
        debug!(
            queue_num,
            backend = "netlink",
            "starting nfqueue netlink backend"
        );
        match NfqueueNetlinkSocket::open(queue_num) {
            Ok(socket) => socket.run(shutdown),
            Err(err) if should_fallback_to_ffi_backend(&err) => {
                warn!(
                    queue_num,
                    detail = %err,
                    "nfqueue netlink socket open failed; delegating to ffi fallback backend"
                );
                NfqueueFfiAdapter::run(queue_num, shutdown)
            }
            Err(err) => Err(err),
        }
    }
}

fn should_fallback_to_ffi_backend(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains("socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) failed")
    })
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result, anyhow};

    use super::should_fallback_to_ffi_backend;

    #[test]
    fn fallback_trigger_matches_socket_open_failure_context() {
        let err = anyhow!("socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) failed: eperm");
        assert!(should_fallback_to_ffi_backend(&err));
    }

    #[test]
    fn fallback_trigger_matches_error_chain_context() {
        let err = (|| -> Result<()> {
            Err(anyhow!("eperm"))
                .context("nfqueue open failed")
                .context("socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) failed")
        })()
        .expect_err("error chain should fail");
        assert!(should_fallback_to_ffi_backend(&err));
    }

    #[test]
    fn fallback_trigger_ignores_non_socket_open_errors() {
        let err = anyhow!("nfqueue netlink config error (seq=1, errno=1)");
        assert!(!should_fallback_to_ffi_backend(&err));
    }
}

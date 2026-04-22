//! Pure-Rust `NETLINK_NETFILTER` backend for NFQUEUE.
//!
//! Replaces the `libnetfilter_queue` C library calls in `platform::ffi::nfqueue` with
//! direct netlink socket I/O.  All packet-parsing, verdict-engine, decision-state, and
//! metrics logic is reused from that module without modification.
//!
//! Enabled by default. Set `OPENSNITCH_NFQUEUE_NETLINK_EXPERIMENT=0` to force the
//! legacy FFI backend; netlink errors cause the worker to fall back automatically.

use std::{
    mem,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use nix::libc;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{RecvFlags, recv},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::platform::ffi::nfqueue::{NfqueueMetricsState, NfqueueVerdictEngine, PacketVerdict};

// ─── Env gate ─────────────────────────────────────────────────────────────────

const OPENSNITCH_NFQUEUE_NETLINK_ENV: &str = "OPENSNITCH_NFQUEUE_NETLINK_EXPERIMENT";

pub(crate) fn nfqueue_netlink_experiment_enabled() -> bool {
    std::env::var(OPENSNITCH_NFQUEUE_NETLINK_ENV)
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

// ─── Protocol constants ───────────────────────────────────────────────────────

/// NETLINK_NETFILTER protocol number (= 12).
const NETLINK_NETFILTER_PROTO: libc::c_int = 12;

/// NFNL subsystem id for nfqueue.
const NFNL_SUBSYS_QUEUE: u16 = 3;

// NFQUEUE netlink message types  (subsys << 8 | local_type)
const NFQNL_MSG_PACKET: u16 = (NFNL_SUBSYS_QUEUE << 8) | 0; // 0x300
const NFQNL_MSG_VERDICT: u16 = (NFNL_SUBSYS_QUEUE << 8) | 1; // 0x301
const NFQNL_MSG_CONFIG: u16 = (NFNL_SUBSYS_QUEUE << 8) | 2; // 0x302

// Standard netlink control message types.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// Netlink flags.
const NLM_F_REQUEST: u16 = 1 << 0;
const NLM_F_ACK: u16 = 1 << 2;

/// nfnetlink protocol version 0.
const NFNETLINK_V0: u8 = 0;

// Queue lifecycle commands  (enum nfqnl_msg_config_cmds).
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;
const NFQNL_CFG_CMD_PF_BIND: u8 = 3;

/// Copy full packet payload.
const NFQNL_COPY_PACKET: u8 = 2;

/// Request uid/gid metadata from the kernel.
const NFQA_CFG_F_UID_GID: u32 = 1 << 3;

// Config attribute types  (enum nfqnl_attr_config).
pub(crate) const NFQA_CFG_CMD: u16 = 1;
pub(crate) const NFQA_CFG_PARAMS: u16 = 2;
pub(crate) const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
pub(crate) const NFQA_CFG_MASK: u16 = 4;
pub(crate) const NFQA_CFG_FLAGS: u16 = 5;

// Packet/verdict attribute types  (enum nfqnl_attr_type).
pub(crate) const NFQA_PACKET_HDR: u16 = 1;
pub(crate) const NFQA_VERDICT_HDR: u16 = 2;
pub(crate) const NFQA_MARK: u16 = 3;
pub(crate) const NFQA_IFINDEX_INDEV: u16 = 5;
pub(crate) const NFQA_IFINDEX_OUTDEV: u16 = 6;
pub(crate) const NFQA_PAYLOAD: u16 = 10;
pub(crate) const NFQA_UID: u16 = 16;

/// Mask stripping NLA_F_NESTED / NLA_F_NET_BYTEORDER from nla_type.
const NLA_TYPE_MASK: u16 = 0x3FFF;

// Fixed header sizes (bytes).
pub(crate) const NLMSG_HDR_LEN: usize = 16;
pub(crate) const NFGENMSG_LEN: usize = 4;
pub(crate) const NLA_HDR_LEN: usize = 4;

// Queue/socket tuning defaults  (matching `platform::ffi::nfqueue`).
const DEFAULT_PACKET_SIZE: u32 = 4096;
const DEFAULT_QUEUE_SIZE: u32 = 4096;
const DEFAULT_SOCKET_RCVBUF_BYTES: i32 = 8 * 1024 * 1024;
const RECV_BUF_LEN: usize = (DEFAULT_PACKET_SIZE * 2) as usize;

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
pub(crate) struct NlMsg(Vec<u8>);

impl NlMsg {
    /// Begin a new message.  `nlmsg_len` is left as a zero placeholder and
    /// patched by [`NlMsg::finalize`].
    pub(crate) fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let mut buf = vec![0u8; NLMSG_HDR_LEN]; // nlmsg_len placeholder + zeros
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        // nlmsg_pid = 0  (kernel fills in our portid on receipt)
        Self(buf)
    }

    /// Append a 4-byte `nfgenmsg` sub-header.
    /// `res_id` (typically queue number) is written in network byte order.
    pub(crate) fn nfgenmsg(mut self, family: u8, res_id: u16) -> Self {
        self.0.push(family);
        self.0.push(NFNETLINK_V0);
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

    let mut offset = NFGENMSG_LEN;
    while offset + NLA_HDR_LEN <= body.len() {
        let nla_len = u16::from_ne_bytes([body[offset], body[offset + 1]]) as usize;
        if nla_len < NLA_HDR_LEN || offset + nla_len > body.len() {
            break;
        }
        let nla_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]) & NLA_TYPE_MASK;
        let data = &body[offset + NLA_HDR_LEN..offset + nla_len];

        match nla_type {
            NFQA_PACKET_HDR => {
                // nfqnl_msg_packet_hdr: packet_id (u32 BE), hw_protocol (u16 BE), hook (u8)
                if data.len() >= 4 {
                    packet_id = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                }
            }
            NFQA_MARK => {
                if data.len() >= 4 {
                    mark = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                }
            }
            NFQA_IFINDEX_INDEV => {
                if data.len() >= 4 {
                    iface_in_idx = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                }
            }
            NFQA_IFINDEX_OUTDEV => {
                if data.len() >= 4 {
                    iface_out_idx = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                }
            }
            NFQA_PAYLOAD => {
                payload = data;
            }
            NFQA_UID => {
                if data.len() >= 4 {
                    uid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                }
            }
            _ => {}
        }

        let step = nla_align(nla_len);
        if step == 0 {
            break;
        }
        offset += step;
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
    fn open(queue_num: u16) -> Result<Self> {
        // SAFETY: standard libc socket/bind syscalls with checked return values.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER_PROTO,
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
        self.send_config_cmd(0, NFQNL_CFG_CMD_PF_BIND, libc::AF_INET as u16, false)?;
        self.send_config_cmd(0, NFQNL_CFG_CMD_PF_BIND, libc::AF_INET6 as u16, false)?;

        // BIND: attach to the specific queue number; request ACK to surface EBUSY early.
        self.send_config_cmd(self.queue_num, NFQNL_CFG_CMD_BIND, 0, true)
            .with_context(|| format!("BIND to queue {} rejected by kernel", self.queue_num))?;

        // COPY_PACKET mode with copy range = DEFAULT_PACKET_SIZE.
        self.send_config_params(self.queue_num, DEFAULT_PACKET_SIZE, NFQNL_COPY_PACKET)?;

        // Queue depth limit.
        self.send_config_maxlen(self.queue_num, DEFAULT_QUEUE_SIZE)?;

        // UID/GID metadata flags – best-effort, older kernels may lack support.
        if let Err(err) =
            self.send_config_flags(self.queue_num, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)
        {
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
            NLM_F_REQUEST | NLM_F_ACK
        } else {
            NLM_F_REQUEST
        };
        let seq = self.next_seq();
        // nfqnl_msg_config_cmd { command (u8), _pad (u8), pf (__be16) }
        let cmd_payload: [u8; 4] = [cmd, 0, (pf >> 8) as u8, pf as u8];
        let msg = NlMsg::new(NFQNL_MSG_CONFIG, flags, seq)
            .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
            .nla_bytes(NFQA_CFG_CMD, &cmd_payload)
            .finalize();
        self.send_raw(&msg)?;
        if request_ack {
            self.recv_ack(seq)?;
        }
        Ok(())
    }

    fn send_config_params(&self, queue_num: u16, copy_range: u32, copy_mode: u8) -> Result<()> {
        let seq = self.next_seq();
        // nfqnl_msg_config_params { copy_range (__be32), copy_mode (u8) } — packed, 5 bytes
        let range = copy_range.to_be_bytes();
        let params: [u8; 5] = [range[0], range[1], range[2], range[3], copy_mode];
        let msg = NlMsg::new(NFQNL_MSG_CONFIG, NLM_F_REQUEST, seq)
            .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
            .nla_bytes(NFQA_CFG_PARAMS, &params)
            .finalize();
        self.send_raw(&msg)
    }

    fn send_config_maxlen(&self, queue_num: u16, max_len: u32) -> Result<()> {
        let seq = self.next_seq();
        let msg = NlMsg::new(NFQNL_MSG_CONFIG, NLM_F_REQUEST, seq)
            .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
            .nla_u32_be(NFQA_CFG_QUEUE_MAXLEN, max_len)
            .finalize();
        self.send_raw(&msg)
    }

    fn send_config_flags(&self, queue_num: u16, mask: u32, flags: u32) -> Result<()> {
        let seq = self.next_seq();
        let msg = NlMsg::new(NFQNL_MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, seq)
            .nfgenmsg(libc::AF_UNSPEC as u8, queue_num)
            .nla_u32_be(NFQA_CFG_MASK, mask)
            .nla_u32_be(NFQA_CFG_FLAGS, flags)
            .finalize();
        self.send_raw(&msg)?;
        self.recv_ack(seq)
    }

    // ── Verdict sender ──────────────────────────────────────────────────────

    fn send_verdict(&self, packet_id: u32, verdict: &PacketVerdict) -> Result<()> {
        let (v, vmark) = NfqueueVerdictEngine::packet_verdict_to_c(verdict);
        let seq = self.next_seq();

        // NFQA_VERDICT_HDR: { verdict (__be32), id/packet_id (__be32) }
        let mut verdict_hdr = [0u8; 8];
        verdict_hdr[0..4].copy_from_slice(&v.to_be_bytes());
        verdict_hdr[4..8].copy_from_slice(&packet_id.to_be_bytes());

        let mut msg = NlMsg::new(NFQNL_MSG_VERDICT, NLM_F_REQUEST, seq)
            .nfgenmsg(libc::AF_UNSPEC as u8, self.queue_num)
            .nla_bytes(NFQA_VERDICT_HDR, &verdict_hdr);

        if vmark != 0 {
            msg = msg.nla_u32_be(NFQA_MARK, vmark);
        }
        if let Some(pkt) = NfqueueVerdictEngine::packet_verdict_payload(verdict) {
            msg = msg.nla_bytes(NFQA_PAYLOAD, pkt);
        }

        self.send_raw(&msg.finalize())
    }

    // ── Socket I/O ──────────────────────────────────────────────────────────

    fn send_raw(&self, buf: &[u8]) -> Result<()> {
        // SAFETY: buf is a valid slice; fd is a valid NETLINK_NETFILTER socket.
        let rc = unsafe { libc::send(self.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
        if rc < 0 {
            bail!("netlink send failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read one netlink reply and check whether it is an ACK for `expected_seq`.
    ///
    /// Tolerates interleaved `NFQNL_MSG_PACKET` messages (they are skipped) so
    /// this can be called safely during the brief configuration window before
    /// netfilter intercept rules become active.
    fn recv_ack(&self, expected_seq: u32) -> Result<()> {
        let mut buf = vec![0u8; 512];
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
            let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
            if msg_type == NLMSG_ERROR {
                // nlmsgerr.error is a negative errno (i32 LE) at offset 16.
                if recv_rc >= NLMSG_HDR_LEN + 4 {
                    let errno = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
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
            // Skip any non-error messages (e.g., a packet racing in).
        }
    }

    // ── Main recv loop ──────────────────────────────────────────────────────

    fn run(self, shutdown: CancellationToken) -> Result<()> {
        let mut buf = vec![0u8; RECV_BUF_LEN];
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
            let mut offset = 0;

            while offset + NLMSG_HDR_LEN <= received.len() {
                let nlmsg_len =
                    u32::from_ne_bytes(received[offset..offset + 4].try_into().unwrap()) as usize;

                if nlmsg_len < NLMSG_HDR_LEN {
                    break;
                }

                let msg_end = (offset + nlmsg_len).min(received.len());
                let msg_type =
                    u16::from_ne_bytes(received[offset + 4..offset + 6].try_into().unwrap());
                let body = &received[offset + NLMSG_HDR_LEN..msg_end];

                match msg_type {
                    NFQNL_MSG_PACKET => {
                        if let Some(pkt) = parse_nfq_packet(body) {
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
                            if let Err(err) = self.send_verdict(pkt.packet_id, &verdict) {
                                warn!(detail = %err, "nfqueue netlink: verdict send failed");
                            }
                        } else {
                            NfqueueMetricsState::record_recv_error(self.queue_num);
                            debug!(
                                "nfqueue netlink: malformed NFQNL_MSG_PACKET (missing packet_id)"
                            );
                        }
                    }
                    NLMSG_ERROR => {
                        if body.len() >= 4 {
                            let errno = i32::from_ne_bytes(body[0..4].try_into().unwrap());
                            if errno != 0 {
                                debug!(errno, "nfqueue netlink error message in recv loop");
                            }
                        }
                    }
                    NLMSG_DONE => break,
                    _ => {}
                }

                let step = nlmsg_align(nlmsg_len);
                if step == 0 {
                    break;
                }
                offset += step;
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
        let cmd: [u8; 4] = [NFQNL_CFG_CMD_UNBIND, 0, 0, 0];
        let msg = NlMsg::new(NFQNL_MSG_CONFIG, NLM_F_REQUEST, seq)
            .nfgenmsg(libc::AF_UNSPEC as u8, self.queue_num)
            .nla_bytes(NFQA_CFG_CMD, &cmd)
            .finalize();
        let _ = self.send_raw(&msg);
    }
}

// ─── Public adapter surface ───────────────────────────────────────────────────

/// Env-gated `NETLINK_NETFILTER` NFQUEUE backend.
///
/// Enabled by default; set `OPENSNITCH_NFQUEUE_NETLINK_EXPERIMENT=0` to disable.
/// The FFI backend remains available as automatic fallback.
pub(crate) struct NfqueueNetlinkAdapter;

impl NfqueueNetlinkAdapter {
    /// Verify that this machine supports `NETLINK_NETFILTER` sockets.
    /// Opens and immediately closes a socket; does not require `CAP_NET_ADMIN`.
    pub(crate) fn preflight() -> Result<()> {
        // SAFETY: socket() return value is checked.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER_PROTO,
            )
        };
        if raw_fd < 0 {
            bail!(
                "nfqueue netlink preflight: socket(NETLINK_NETFILTER) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: raw_fd is a valid, open file descriptor.
        unsafe { libc::close(raw_fd) };
        Ok(())
    }

    /// Run the NFQUEUE recv/verdict loop for `queue_num` until `shutdown` is cancelled.
    ///
    /// `NfqueueRuntimeState::init` must be called before this method.
    pub(crate) fn run(queue_num: u16, shutdown: CancellationToken) -> Result<()> {
        debug!(
            queue_num,
            backend = "netlink",
            "starting nfqueue netlink backend"
        );
        let socket = NfqueueNetlinkSocket::open(queue_num)?;
        socket.run(shutdown)
    }
}

//! Pure-Rust `NETLINK_NETFILTER` backend for NFQUEUE.
//!
//! Replaces the `libnetfilter_queue` C library calls in `platform::nfqueue::ffi` with
//! direct netlink socket I/O.  All packet-parsing, verdict-engine, decision-state, and
//! metrics logic is reused from that module without modification.
//!
//! Canonical NFQUEUE backend using `NETLINK_NETFILTER`.

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use nix::libc;
use rustix::io::Errno;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::platform::netlink::message::{NetlinkResponse, RawNetlinkPayload};
use crate::platform::netlink::socket::SyncNetlinkSocket;
use crate::platform::nfqueue::ffi::lifecycle::NfqueueFfiAdapter;
use crate::platform::nfqueue::metrics::NfqueueMetricsState;
use crate::platform::nfqueue::queue_wire::{
    DefaultNlMsgFactory, NFGENMSG_LEN, NLA_HDR_LEN, NLMSG_HDR_LEN, NfqPacket, NfqueueNlMsgExt,
    NlMsgFactory, NlmsgIter, nla_align, read_ne_i32,
};
use crate::platform::nfqueue::verdict::{NfqueueVerdictEngine, PacketVerdict};

// ─── Protocol constants ───────────────────────────────────────────────────────

// NFQUEUE netlink message types  (subsys << 8 | local_type)
const NFQNL_MSG_PACKET: u16 =
    ((libc::NFNL_SUBSYS_QUEUE as u16) << 8) | (libc::NFQNL_MSG_PACKET as u16);
const NFQNL_MSG_VERDICT: u16 =
    ((libc::NFNL_SUBSYS_QUEUE as u16) << 8) | (libc::NFQNL_MSG_VERDICT as u16);
const NFQNL_MSG_CONFIG: u16 =
    ((libc::NFNL_SUBSYS_QUEUE as u16) << 8) | (libc::NFQNL_MSG_CONFIG as u16);

// Queue/socket tuning defaults  (matching `platform::nfqueue::ffi`).
const DEFAULT_PACKET_SIZE: u32 = 4096;
const DEFAULT_QUEUE_SIZE: u32 = 4096;
const DEFAULT_SOCKET_RCVBUF_BYTES: i32 = 8 * 1024 * 1024;
const RECV_BUF_LEN: usize = (DEFAULT_PACKET_SIZE * 2) as usize;
const ACK_RECV_BUF_LEN: usize = 512;

/// Pre-computed verdict message capacity: nlmsg_hdr + nfgenmsg + verdict_hdr NLA + mark NLA.
const VERDICT_BUF_CAPACITY: usize =
    NLMSG_HDR_LEN + NFGENMSG_LEN + (NLA_HDR_LEN + 8) + (NLA_HDR_LEN + 4);

// ─── Socket lifecycle ─────────────────────────────────────────────────────────

struct NfqueueNetlinkSocket {
    sock: SyncNetlinkSocket,
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
        let sock = SyncNetlinkSocket::open(libc::NETLINK_NETFILTER as u16)?;
        sock.set_recv_buf_size(DEFAULT_SOCKET_RCVBUF_BYTES);
        sock.set_no_enobufs();

        let s = Self {
            sock,
            queue_num,
            seq: AtomicU32::new(1),
        };
        s.configure_queue()
            .with_context(|| format!("nfqueue netlink queue {} configuration failed", queue_num))?;
        Ok(s)
    }

    // ── Socket I/O ──────────────────────────────────────────────────────────

    fn send_raw(&self, buf: &[u8]) -> Result<()> {
        self.sock.send(buf)
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
        let msg = DefaultNlMsgFactory::new_message(
            NFQNL_MSG_CONFIG,
            flags,
            seq,
            NFGENMSG_LEN + NLA_HDR_LEN + 4,
        )
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
        let msg = DefaultNlMsgFactory::new_message(
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
        let msg = DefaultNlMsgFactory::new_message(
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
        let msg = DefaultNlMsgFactory::new_message(
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

        let mut msg = DefaultNlMsgFactory::reuse_message(
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
            if !self
                .sock
                .poll_readable(remaining)
                .context("poll nfqueue ack")?
            {
                bail!("nfqueue netlink ack timeout (seq={})", expected_seq);
            }
            let recv_rc = match self.sock.try_recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e == Errno::AGAIN || e == Errno::WOULDBLOCK => continue,
                Err(e) => bail!("nfqueue netlink ack recv: {}", e),
            };
            if recv_rc < NLMSG_HDR_LEN {
                continue;
            }

            let received = RawNetlinkPayload::load(&buf[..recv_rc]);
            for msg in NlmsgIter::new(received.payload) {
                if msg.msg_type == libc::NLMSG_ERROR as u16 && msg.seq == expected_seq {
                    // nlmsgerr.error is a negative errno (i32 LE) at offset 16.
                    if let Some(errno) = read_ne_i32(msg.payload) {
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
        let poll_timeout = Duration::from_millis(500);

        debug!(
            queue_num = self.queue_num,
            backend = "netlink",
            "nfqueue netlink backend started"
        );

        while !shutdown.is_cancelled() {
            Self::maybe_log_metrics(self.queue_num, &mut last_metrics_log);

            if !self
                .sock
                .poll_readable(poll_timeout)
                .context("poll nfqueue netlink fd")?
            {
                continue;
            }

            let recv_rc = match self.sock.try_recv(&mut buf) {
                Ok(n) => n,
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

            let received = RawNetlinkPayload::load(&buf[..recv_rc]);
            for msg in NlmsgIter::new(received.payload) {
                match msg.msg_type {
                    NFQNL_MSG_PACKET => {
                        if let Some(pkt) = NfqPacket::decode(&msg) {
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
                        if let Some(errno) = read_ne_i32(msg.payload) {
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
        let msg = DefaultNlMsgFactory::new_message(
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

pub(crate) fn should_fallback_to_ffi_backend(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let s = cause.to_string();
        s.contains("socket(AF_NETLINK, SOCK_RAW,") && s.contains(") failed")
    })
}

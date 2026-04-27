//! Synchronous netlink socket for protocols that need fine-grained fd-level
//! control (e.g. `NETLINK_NETFILTER` / NFQUEUE).
//!
//! Unlike the async `NetlinkSocket` / `MulticastSocketRaw` from `netlink-socket2`,
//! this socket exposes poll-based blocking recv and direct send — suitable for
//! tight per-packet loops on a dedicated thread.

use std::{
    mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    time::Duration,
};

use anyhow::{Result, bail};
use nix::libc;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{RecvFlags, SendFlags, recv, send},
};
use tracing::debug;

/// A raw `AF_NETLINK` socket with synchronous poll/recv/send.
pub(crate) struct SyncNetlinkSocket {
    fd: OwnedFd,
}

impl SyncNetlinkSocket {
    /// Open a raw `AF_NETLINK` socket for `protocol` (e.g.
    /// `libc::NETLINK_NETFILTER`) and bind it to the kernel.
    pub(crate) fn open(protocol: u16) -> Result<Self> {
        // SAFETY: standard libc socket/bind syscalls with checked return values.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol as libc::c_int,
            )
        };
        if raw_fd < 0 {
            bail!(
                "socket(AF_NETLINK, SOCK_RAW, {}) failed: {}",
                protocol,
                std::io::Error::last_os_error()
            );
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // SAFETY: sockaddr_nl is a plain C struct; zero-initialising satisfies all
        // alignment requirements, and we overwrite the meaningful fields below.
        let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // nl_pid = 0  → kernel assigns our netlink portid
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

        Ok(Self { fd })
    }

    /// Set `SO_RCVBUF` on the socket.  Best-effort; logs on failure.
    pub(crate) fn set_recv_buf_size(&self, size: i32) {
        // SAFETY: setsockopt called with correct type + size.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            debug!(
                err = %std::io::Error::last_os_error(),
                "SyncNetlinkSocket: SO_RCVBUF tuning failed"
            );
        }
    }

    /// Enable `NETLINK_NO_ENOBUFS` on the socket.  Best-effort; logs on failure.
    pub(crate) fn set_no_enobufs(&self) {
        let one: libc::c_int = 1;
        // SAFETY: setsockopt called with correct type + size.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_NO_ENOBUFS,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            debug!(
                err = %std::io::Error::last_os_error(),
                "SyncNetlinkSocket: NETLINK_NO_ENOBUFS not applied"
            );
        }
    }

    /// Send a netlink message.
    pub(crate) fn send(&self, buf: &[u8]) -> Result<()> {
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

    /// Poll for readability, then return.
    ///
    /// Returns `true` if the socket became readable within `timeout`, `false`
    /// on timeout.
    pub(crate) fn poll_readable(&self, timeout: Duration) -> Result<bool> {
        let ts = Timespec::try_from(timeout).ok();
        // SAFETY: self.fd is valid for the duration of this call.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) };
        let mut pfd = [PollFd::new(&borrowed, PollFlags::IN)];
        let n = poll(&mut pfd, ts.as_ref()).map_err(|e| anyhow::anyhow!("poll failed: {e}"))?;
        Ok(n > 0 && pfd[0].revents().contains(PollFlags::IN))
    }

    /// Non-blocking recv.
    ///
    /// Returns `Ok(n)` on success, `Err(Errno::AGAIN)` / `Err(Errno::WOULDBLOCK)`
    /// when no data is available, or another `Err` on real failures.  Callers
    /// can match on specific `Errno` values (e.g. `Errno::NOBUFS`).
    pub(crate) fn try_recv(&self, buf: &mut [u8]) -> std::result::Result<usize, Errno> {
        recv(self.fd.as_fd(), buf, RecvFlags::DONTWAIT).map(|(n, _)| n)
    }
}

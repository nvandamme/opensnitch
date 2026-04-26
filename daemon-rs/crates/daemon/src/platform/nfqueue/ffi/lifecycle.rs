use std::{
    ffi::c_void,
    io,
    os::raw::{c_char, c_int},
    ptr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use nix::libc;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::BorrowedFd,
    io::Errno,
    net::{RecvFlags, recv},
};
use tracing::{debug, warn};

use super::{
    nfq_bind_pf, nfq_close, nfq_create_queue, nfq_destroy_queue, nfq_fd, nfq_handle,
    nfq_handle_packet, nfq_open, nfq_q_handle, nfq_set_mode, nfq_set_queue_flags,
    nfq_set_queue_maxlen, nfq_unbind_pf, nfqueue_callback,
};
use crate::platform::nfqueue::metrics::NfqueueMetricsState;
use crate::platform::nfqueue::state::{
    DEFAULT_PACKET_SIZE, DEFAULT_QUEUE_SIZE, DEFAULT_SOCKET_RCVBUF_BYTES,
};

pub(crate) struct QueueRuntime {
    pub(super) h: *mut nfq_handle,
    pub(super) qh: *mut nfq_q_handle,
    pub(super) fd: c_int,
    pub(super) queue_num: u16,
}

pub(crate) struct NfqueueFfiAdapter;

impl NfqueueFfiAdapter {
    pub(crate) fn run(queue_num: u16, shutdown: tokio_util::sync::CancellationToken) -> Result<()> {
        let q = QueueRuntime::open(queue_num)?;
        q.run(shutdown)
    }
}

// SAFETY: QueueRuntime wraps C pointers that are only accessed on the single queue
// thread and cleaned up in Drop. Covenanting to not share raw pointers across threads.
unsafe impl Send for QueueRuntime {}

impl QueueRuntime {
    pub(crate) fn open(queue_num: u16) -> Result<Self> {
        // SAFETY: nfqueue C API pointers are checked for null / return values.
        unsafe {
            let h = nfq_open();
            if h.is_null() {
                bail!("nfq_open failed");
            }

            let _ = nfq_unbind_pf(h, libc::AF_INET as u16);
            let _ = nfq_unbind_pf(h, libc::AF_INET6 as u16);

            if nfq_bind_pf(h, libc::AF_INET as u16) < 0 {
                let _ = nfq_close(h);
                bail!("nfq_bind_pf(AF_INET) failed");
            }
            if nfq_bind_pf(h, libc::AF_INET6 as u16) < 0 {
                let _ = nfq_close(h);
                bail!("nfq_bind_pf(AF_INET6) failed");
            }

            let qh = nfq_create_queue(
                h,
                queue_num,
                Some(nfqueue_callback),
                queue_num as usize as *mut c_void,
            );
            if qh.is_null() {
                let _ = nfq_close(h);
                bail!("nfq_create_queue failed for queue {queue_num}");
            }

            let flags_rc = nfq_set_queue_flags(
                qh,
                libc::NFQA_CFG_F_UID_GID as u32,
                libc::NFQA_CFG_F_UID_GID as u32,
            );
            if flags_rc < 0 {
                debug!(
                    queue_num,
                    "nfqueue uid/gid metadata flags unavailable; continuing without queue flags"
                );
            }

            if nfq_set_queue_maxlen(qh, DEFAULT_QUEUE_SIZE) < 0 {
                let _ = nfq_destroy_queue(qh);
                let _ = nfq_close(h);
                bail!("nfq_set_queue_maxlen failed");
            }

            if nfq_set_mode(qh, libc::NFQNL_COPY_PACKET as u8, DEFAULT_PACKET_SIZE) < 0 {
                let _ = nfq_destroy_queue(qh);
                let _ = nfq_close(h);
                bail!("nfq_set_mode COPY_PACKET failed");
            }

            let fd = nfq_fd(h);
            if fd < 0 {
                let _ = nfq_destroy_queue(qh);
                let _ = nfq_close(h);
                bail!("nfq_fd failed");
            }

            Self::tune_netlink_no_enobufs(fd);
            Self::tune_socket_recv_buffer(fd, DEFAULT_SOCKET_RCVBUF_BYTES);

            Ok(Self {
                h,
                qh,
                fd,
                queue_num,
            })
        }
    }

    pub(crate) fn run(self, shutdown: tokio_util::sync::CancellationToken) -> Result<()> {
        let mut buf = vec![0_u8; (DEFAULT_PACKET_SIZE * 2) as usize];
        let mut last_metrics_log = Instant::now();
        // SAFETY: self.fd comes from nfq_fd and remains valid for the lifetime of this loop.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let timeout = Timespec::try_from(Duration::from_millis(500)).ok();

        while !shutdown.is_cancelled() {
            NfqueueMetricsState::maybe_log_queue_metrics(self.queue_num, &mut last_metrics_log);

            let mut pfd = [PollFd::new(&borrowed_fd, PollFlags::IN)];
            let poll_rc = poll(&mut pfd, timeout.as_ref()).context("poll nfqueue fd")?;
            if poll_rc == 0 {
                continue;
            }

            let flags = pfd[0].revents();
            if !flags.contains(PollFlags::IN) {
                continue;
            }

            let recv_rc = match recv(borrowed_fd, &mut buf, RecvFlags::DONTWAIT) {
                Ok((bytes_read, _recv_total_len)) => bytes_read,
                Err(err) => {
                    if err != Errno::WOULDBLOCK && err != Errno::AGAIN {
                        let io_err = io::Error::from_raw_os_error(err.raw_os_error());
                        NfqueueMetricsState::record_recv_error(self.queue_num);
                        if err == Errno::NOBUFS {
                            debug!("nfqueue recv overflow (ENOBUFS): {io_err}");
                        } else {
                            warn!("nfqueue recv failed: {io_err}");
                        }
                    }
                    continue;
                }
            };
            if recv_rc == 0 {
                NfqueueMetricsState::record_recv_error(self.queue_num);
                warn!("nfqueue recv returned EOF");
                continue;
            }

            if recv_rc > c_int::MAX as usize {
                NfqueueMetricsState::record_recv_error(self.queue_num);
                warn!("nfqueue recv size overflow: {}", recv_rc);
                continue;
            }

            // SAFETY: recv_rc bytes were written into buf by recv.
            let handle_rc = unsafe {
                nfq_handle_packet(self.h, buf.as_mut_ptr().cast::<c_char>(), recv_rc as c_int)
            };
            if handle_rc < 0 {
                let io_err = io::Error::last_os_error();
                let errno = io_err.raw_os_error().unwrap_or_default();
                if errno == libc::ENOBUFS || errno == libc::EAGAIN || errno == libc::EINTR {
                    debug!(rc = handle_rc, errno, "nfq_handle_packet transient failure");
                } else {
                    warn!(rc = handle_rc, errno, "nfq_handle_packet failed");
                }
            }
        }

        Ok(())
    }

    fn tune_socket_recv_buffer(fd: c_int, size: i32) {
        // SAFETY: setsockopt is called with a valid nfqueue fd and a properly sized integer buffer.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const i32).cast::<c_void>(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            warn!(
                requested_bytes = size,
                err = %err,
                "nfqueue socket recv buffer tuning failed"
            );
        }
    }

    fn tune_netlink_no_enobufs(fd: c_int) {
        let value: i32 = 1;
        // SAFETY: setsockopt is called with a valid nfqueue netlink fd and integer option payload.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                libc::NETLINK_NO_ENOBUFS,
                (&value as *const i32).cast::<c_void>(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            debug!(err = %err, "nfqueue netlink no_enobufs tuning not applied");
        }
    }
}

impl Drop for QueueRuntime {
    fn drop(&mut self) {
        // SAFETY: pointers are created by libnetfilter_queue and may be null.
        unsafe {
            if !self.qh.is_null() {
                let _ = nfq_destroy_queue(self.qh);
                self.qh = ptr::null_mut();
            }
            if !self.h.is_null() {
                let _ = nfq_close(self.h);
                self.h = ptr::null_mut();
            }
        }
    }
}

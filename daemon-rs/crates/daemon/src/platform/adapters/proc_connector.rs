use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};

use anyhow::Result;
use netlink_sys::{Socket, SocketAddr};
use nix::libc;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::BorrowedFd,
    thread::{LinkNameSpaceType, move_into_link_name_space},
};

use crate::{
    models::proc_event::{ProcEventKind, ProcPidEvent},
    utils::byte_read::read_ne_value_at,
};

const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

pub(crate) const NLMSG_HDR_LEN: usize = 16;
pub(crate) const CN_MSG_LEN: usize = 20;
pub(crate) const PROC_EVENT_HEADER_LEN: usize = 16;
pub(crate) const PROC_EVENT_EXEC_PID_OFFSET: usize = 16;
pub(crate) const PROC_EVENT_FORK_CHILD_PID_OFFSET: usize = 24;

pub(crate) const PROC_EVENT_FORK: u32 = 0x0000_0001;
pub(crate) const PROC_EVENT_EXEC: u32 = 0x0000_0002;
pub(crate) const PROC_EVENT_EXIT: u32 = 0x8000_0000;

pub struct ProcEventSocket {
    pub(crate) sock: Socket,
}

impl ProcEventSocket {
    pub fn recv_pid_event(&self, timeout: Duration) -> Result<Option<ProcPidEvent>> {
        let mut buf = vec![0_u8; 4096];
        let Some(size) = Self::recv_with_timeout(&self.sock, &mut buf, timeout)? else {
            return Ok(None);
        };

        Ok(Self::parse_pid_event(&buf[..size]))
    }

    fn connector_payload(frame: &[u8]) -> Option<&[u8]> {
        let payload_offset = NLMSG_HDR_LEN + CN_MSG_LEN;
        let min_len = payload_offset + PROC_EVENT_HEADER_LEN;
        if frame.len() < min_len {
            return None;
        }

        let payload = &frame[payload_offset..];
        let cn_msg_data_len = read_ne_value_at(frame, NLMSG_HDR_LEN + 16, u16::from_ne_bytes)? as usize;
        if cn_msg_data_len == 0 {
            return None;
        }
        if payload.len() < cn_msg_data_len {
            return None;
        }

        Some(&payload[..cn_msg_data_len])
    }

    fn parse_pid_event(frame: &[u8]) -> Option<ProcPidEvent> {
        let payload = Self::connector_payload(frame)?;
        let what = read_ne_value_at(payload, 0, u32::from_ne_bytes)?;

        match what {
            PROC_EVENT_EXEC | PROC_EVENT_EXIT => {
                let pid =
                    read_ne_value_at(payload, PROC_EVENT_EXEC_PID_OFFSET, u32::from_ne_bytes)?;
                let kind = if what == PROC_EVENT_EXEC {
                    ProcEventKind::Exec
                } else {
                    ProcEventKind::Exit
                };
                Some(ProcPidEvent { pid, kind })
            }
            PROC_EVENT_FORK => {
                let pid = read_ne_value_at(
                    payload,
                    PROC_EVENT_FORK_CHILD_PID_OFFSET,
                    u32::from_ne_bytes,
                )?;
                Some(ProcPidEvent {
                    pid,
                    kind: ProcEventKind::Fork,
                })
            }
            _ => None,
        }
    }

    fn recv_with_timeout(
        sock: &Socket,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<usize>> {
        // SAFETY: socket fd stays valid for the duration of this function.
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
        let mut pfd = [PollFd::new(&borrowed_fd, PollFlags::IN)];
        let timeout_ts = Timespec::try_from(timeout).ok();

        let poll_rc = poll(&mut pfd, timeout_ts.as_ref())?;
        if poll_rc == 0 {
            return Ok(None);
        }

        if !pfd[0].revents().contains(PollFlags::IN) {
            return Ok(None);
        }

        match sock.recv(&mut &mut buf[..], libc::MSG_DONTWAIT) {
            Ok(size) => Ok(Some(size)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn switch_to_host_netns() -> Result<()> {
        let host_netns = std::fs::File::open("/proc/1/ns/net")?;
        move_into_link_name_space(host_netns.as_fd(), Some(LinkNameSpaceType::Network))?;
        Ok(())
    }

    fn build_listen_msg() -> Vec<u8> {
        let mut msg = vec![0_u8; 40];

        // nlmsghdr
        msg[0..4].copy_from_slice(&(40_u32).to_ne_bytes());
        msg[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        msg[6..8].copy_from_slice(&(0_u16).to_ne_bytes());
        msg[8..12].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[12..16].copy_from_slice(&(std::process::id()).to_ne_bytes());

        // cn_msg
        msg[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg[24..28].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[28..32].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[32..34].copy_from_slice(&(4_u16).to_ne_bytes());
        msg[34..36].copy_from_slice(&(0_u16).to_ne_bytes());

        // proc_cn_mcast_op
        msg[36..40].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());

        msg
    }

    pub fn open() -> Result<Self> {
        let _ = Self::switch_to_host_netns();
        let mut sock = Socket::new(libc::NETLINK_CONNECTOR as isize)?;
        sock.bind(&SocketAddr::new(std::process::id(), CN_IDX_PROC))?;
        sock.send_to(&Self::build_listen_msg(), &SocketAddr::new(0, 0), 0)?;
        Ok(Self { sock })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_read_u16_ne_at(frame: &[u8], offset: usize) -> Option<u16> {
        read_ne_value_at(frame, offset, u16::from_ne_bytes)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_read_u32_ne_at(frame: &[u8], offset: usize) -> Option<u32> {
        read_ne_value_at(frame, offset, u32::from_ne_bytes)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_connector_payload(frame: &[u8]) -> Option<&[u8]> {
        Self::connector_payload(frame)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_pid_event(frame: &[u8]) -> Option<ProcPidEvent> {
        Self::parse_pid_event(frame)
    }
}

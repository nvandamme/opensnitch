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

use crate::models::proc_event::{ProcEventKind, ProcEventSocket, ProcPidEvent};

const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

const NLMSG_HDR_LEN: usize = 16;
const CN_MSG_LEN: usize = 20;
const PROC_EVENT_HEADER_LEN: usize = 16;
const PROC_EVENT_EXEC_PID_OFFSET: usize = 16;
const PROC_EVENT_FORK_CHILD_PID_OFFSET: usize = 24;

const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

trait ProcConnectorFrameExt {
    fn parse_proc_pid_event(&self) -> Option<ProcPidEvent>;
    fn connector_payload(&self) -> Option<&[u8]>;
    fn read_u16_ne_at(&self, offset: usize) -> Option<u16>;
    fn read_u32_ne_at(&self, offset: usize) -> Option<u32>;
}

impl ProcConnectorFrameExt for [u8] {
    fn parse_proc_pid_event(&self) -> Option<ProcPidEvent> {
        let payload = self.connector_payload()?;
        let what = payload.read_u32_ne_at(0)?;

        match what {
            PROC_EVENT_EXEC | PROC_EVENT_EXIT => {
                let pid = payload.read_u32_ne_at(PROC_EVENT_EXEC_PID_OFFSET)?;
                let kind = if what == PROC_EVENT_EXEC {
                    ProcEventKind::Exec
                } else {
                    ProcEventKind::Exit
                };
                Some(ProcPidEvent { pid, kind })
            }
            PROC_EVENT_FORK => {
                let pid = payload.read_u32_ne_at(PROC_EVENT_FORK_CHILD_PID_OFFSET)?;
                Some(ProcPidEvent {
                    pid,
                    kind: ProcEventKind::Fork,
                })
            }
            _ => None,
        }
    }

    fn connector_payload(&self) -> Option<&[u8]> {
        let payload_offset = NLMSG_HDR_LEN + CN_MSG_LEN;
        let min_len = payload_offset + PROC_EVENT_HEADER_LEN;
        if self.len() < min_len {
            return None;
        }

        let payload = &self[payload_offset..];
        let cn_msg_data_len = self.read_u16_ne_at(NLMSG_HDR_LEN + 16)? as usize;
        if cn_msg_data_len == 0 {
            return None;
        }
        if payload.len() < cn_msg_data_len {
            return None;
        }

        Some(&payload[..cn_msg_data_len])
    }

    fn read_u16_ne_at(&self, offset: usize) -> Option<u16> {
        let bytes = self.get(offset..offset + 2)?;
        Some(u16::from_ne_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_ne_at(&self, offset: usize) -> Option<u32> {
        let bytes = self.get(offset..offset + 4)?;
        Some(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl ProcEventSocket {
    pub fn recv_pid_event(&self, timeout: Duration) -> Result<Option<ProcPidEvent>> {
        let mut buf = vec![0_u8; 4096];
        let Some(size) = recv_with_timeout(&self.sock, &mut buf, timeout)? else {
            return Ok(None);
        };

        Ok(buf[..size].parse_proc_pid_event())
    }
}

pub fn open_proc_events() -> Result<ProcEventSocket> {
    let _ = switch_to_host_netns();
    let mut sock = Socket::new(libc::NETLINK_CONNECTOR as isize)?;
    sock.bind(&SocketAddr::new(std::process::id(), CN_IDX_PROC))?;
    sock.send_to(&build_proc_listen_msg(), &SocketAddr::new(0, 0), 0)?;
    Ok(ProcEventSocket { sock })
}

fn recv_with_timeout(sock: &Socket, buf: &mut [u8], timeout: Duration) -> Result<Option<usize>> {
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

fn build_proc_listen_msg() -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_frame(what: u32, pid: u32, is_fork: bool) -> Vec<u8> {
        let total = NLMSG_HDR_LEN + CN_MSG_LEN + 32;
        let mut frame = vec![0_u8; total];

        // nlmsghdr.nlmsg_len
        frame[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
        // cn_msg.len
        frame[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&(32_u16).to_ne_bytes());
        // proc_event.what
        let payload_offset = NLMSG_HDR_LEN + CN_MSG_LEN;
        frame[payload_offset..payload_offset + 4].copy_from_slice(&what.to_ne_bytes());

        let pid_offset = if is_fork {
            payload_offset + PROC_EVENT_FORK_CHILD_PID_OFFSET
        } else {
            payload_offset + PROC_EVENT_EXEC_PID_OFFSET
        };
        frame[pid_offset..pid_offset + 4].copy_from_slice(&pid.to_ne_bytes());

        frame
    }

    #[test]
    fn parse_proc_pid_event_exec() {
        let frame = build_frame(PROC_EVENT_EXEC, 1234, false);
        let parsed = frame.parse_proc_pid_event().unwrap();
        assert_eq!(parsed.pid, 1234);
        assert!(matches!(parsed.kind, ProcEventKind::Exec));
    }

    #[test]
    fn parse_proc_pid_event_exit() {
        let frame = build_frame(PROC_EVENT_EXIT, 4321, false);
        let parsed = frame.parse_proc_pid_event().unwrap();
        assert_eq!(parsed.pid, 4321);
        assert!(matches!(parsed.kind, ProcEventKind::Exit));
    }

    #[test]
    fn parse_proc_pid_event_fork_uses_child_pid() {
        let frame = build_frame(PROC_EVENT_FORK, 777, true);
        let parsed = frame.parse_proc_pid_event().unwrap();
        assert_eq!(parsed.pid, 777);
        assert!(matches!(parsed.kind, ProcEventKind::Fork));
    }

    #[test]
    fn parse_proc_pid_event_rejects_short_or_empty_frames() {
        assert!([].parse_proc_pid_event().is_none());

        let mut frame = build_frame(PROC_EVENT_EXEC, 10, false);
        frame.truncate(NLMSG_HDR_LEN + CN_MSG_LEN + PROC_EVENT_HEADER_LEN - 1);
        assert!(frame.parse_proc_pid_event().is_none());

        let mut frame = build_frame(PROC_EVENT_EXEC, 10, false);
        frame[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&(0_u16).to_ne_bytes());
        assert!(frame.parse_proc_pid_event().is_none());
    }
}

use std::{os::fd::AsFd, time::Duration};

use anyhow::{Result, anyhow};
use netlink_bindings::traits::{NetlinkRequest, Protocol};
use netlink_socket2::{MulticastSocketRaw, NetlinkSocket};
use nix::libc;
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

use crate::{
    models::proc_event::{ProcEventKind, ProcPidEvent},
    utils::byte_read::read_ne_value_at,
};

const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

#[cfg(test)]
pub(crate) const NLMSG_HDR_LEN: usize = 16;
pub(crate) const CN_MSG_LEN: usize = 20;
pub(crate) const PROC_EVENT_HEADER_LEN: usize = 16;
pub(crate) const PROC_EVENT_EXEC_PID_OFFSET: usize = 16;
pub(crate) const PROC_EVENT_FORK_CHILD_PID_OFFSET: usize = 24;
const PROC_CONNECTOR_OPEN_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) const PROC_EVENT_FORK: u32 = 0x0000_0001;
pub(crate) const PROC_EVENT_EXEC: u32 = 0x0000_0002;
pub(crate) const PROC_EVENT_EXIT: u32 = 0x8000_0000;

pub struct ProcEventSocket {
    // Request socket retained for staged connector control paths.
    #[allow(dead_code)]
    pub(crate) request_sock: NetlinkSocket,
    pub(crate) event_sock: MulticastSocketRaw,
}

struct ProcListenRequest {
    payload: [u8; CN_MSG_LEN + 4],
}

impl NetlinkRequest for ProcListenRequest {
    fn protocol(&self) -> Protocol {
        Protocol::Raw {
            protonum: libc::NETLINK_CONNECTOR as u16,
            request_type: libc::NLMSG_DONE as u16,
        }
    }

    fn flags(&self) -> u16 {
        0
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    type ReplyType<'buf> = &'buf [u8];

    fn decode_reply<'buf>(buf: &'buf [u8]) -> Self::ReplyType<'buf> {
        buf
    }
}

impl ProcEventSocket {
    #[cfg(test)]
    pub fn recv_pid_event(&mut self, timeout: Duration) -> Result<Option<ProcPidEvent>> {
        Self::run_netlink_future(self.recv_pid_event_async(timeout))
    }

    pub async fn recv_pid_event_async(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProcPidEvent>> {
        let recv = match tokio::time::timeout(timeout, self.event_sock.recv()).await {
            Ok(Ok(recv)) => recv,
            Ok(Err(err)) => return Err(anyhow::Error::new(err)),
            Err(_) => return Ok(None),
        };

        let (_meta, payload) = recv;
        Ok(Self::parse_pid_event_from_payload(payload))
    }

    #[cfg(test)]
    fn connector_payload(frame: &[u8]) -> Option<&[u8]> {
        let payload_offset = NLMSG_HDR_LEN + CN_MSG_LEN;
        let min_len = payload_offset + PROC_EVENT_HEADER_LEN;
        if frame.len() < min_len {
            return None;
        }

        let payload = &frame[payload_offset..];
        let cn_msg_data_len =
            read_ne_value_at(frame, NLMSG_HDR_LEN + 16, u16::from_ne_bytes)? as usize;
        if cn_msg_data_len == 0 {
            return None;
        }
        if payload.len() < cn_msg_data_len {
            return None;
        }

        Some(&payload[..cn_msg_data_len])
    }

    #[cfg(test)]
    fn parse_pid_event(frame: &[u8]) -> Option<ProcPidEvent> {
        let payload = Self::connector_payload(frame)?;
        Self::parse_pid_event_payload(payload)
    }

    fn parse_pid_event_from_payload(payload: &[u8]) -> Option<ProcPidEvent> {
        if payload.len() < PROC_EVENT_HEADER_LEN {
            return None;
        }

        Self::parse_pid_event_payload(payload)
    }

    fn parse_pid_event_payload(payload: &[u8]) -> Option<ProcPidEvent> {
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

    fn run_netlink_future<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::new)?
            .block_on(future)
    }

    fn run_netlink_future_compat<T: Send + 'static>(
        future: impl std::future::Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return std::thread::spawn(move || Self::run_netlink_future(future))
                .join()
                .map_err(|_| anyhow::anyhow!("failed to join netlink compatibility thread"))?;
        }

        Self::run_netlink_future(future)
    }

    fn switch_to_host_netns() -> Result<()> {
        let host_netns = std::fs::File::open("/proc/1/ns/net")?;
        move_into_link_name_space(host_netns.as_fd(), Some(LinkNameSpaceType::Network))?;
        Ok(())
    }

    fn build_listen_payload() -> [u8; CN_MSG_LEN + 4] {
        let mut msg = [0_u8; CN_MSG_LEN + 4];

        // cn_msg
        msg[0..4].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg[4..8].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg[8..12].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[12..16].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[16..18].copy_from_slice(&(4_u16).to_ne_bytes());
        msg[18..20].copy_from_slice(&(0_u16).to_ne_bytes());

        // proc_cn_mcast_op
        msg[20..24].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());

        msg
    }

    pub fn open() -> Result<Self> {
        Self::run_netlink_future_compat(Self::open_async())
    }

    pub async fn open_async() -> Result<Self> {
        let _ = Self::switch_to_host_netns();

        let mut request_sock = NetlinkSocket::new();
        let mut event_sock = MulticastSocketRaw::new(libc::NETLINK_CONNECTOR as u16)?;
        event_sock.listen(CN_IDX_PROC)?;

        let request = ProcListenRequest {
            payload: Self::build_listen_payload(),
        };
        let mut iter =
            tokio::time::timeout(PROC_CONNECTOR_OPEN_TIMEOUT, request_sock.request(&request))
                .await
                .map_err(|_| anyhow!("proc connector request timed out"))??;
        tokio::time::timeout(PROC_CONNECTOR_OPEN_TIMEOUT, iter.recv_ack())
            .await
            .map_err(|_| anyhow!("proc connector ack timed out"))?
            .map_err(anyhow::Error::new)?;

        Ok(Self {
            request_sock,
            event_sock,
        })
    }

    #[cfg(test)]
    pub(crate) fn probe_read_u16_ne_at(frame: &[u8], offset: usize) -> Option<u16> {
        read_ne_value_at(frame, offset, u16::from_ne_bytes)
    }

    #[cfg(test)]
    pub(crate) fn probe_read_u32_ne_at(frame: &[u8], offset: usize) -> Option<u32> {
        read_ne_value_at(frame, offset, u32::from_ne_bytes)
    }

    #[cfg(test)]
    pub(crate) fn probe_connector_payload(frame: &[u8]) -> Option<&[u8]> {
        Self::connector_payload(frame)
    }

    #[cfg(test)]
    pub(crate) fn probe_parse_pid_event(frame: &[u8]) -> Option<ProcPidEvent> {
        Self::parse_pid_event(frame)
    }
}

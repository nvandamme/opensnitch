use std::{os::fd::AsFd, time::Duration};

use anyhow::Result;
#[cfg(test)]
use netlink_bindings::builtin;
use netlink_bindings::traits::{NetlinkRequest, Protocol};
use netlink_socket2::MulticastSocketRaw;
use nix::libc;
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

use crate::{
    models::proc_event::{ProcEventKind, ProcPidEvent},
    platform::netlink::control::should_process_nlmsg_payload,
    platform::netlink::io::{
        open_and_listen_multicast_socket, recv_with_timeout, request_with_ack_timeout,
    },
    platform::netlink::runtime::run_on_netlink_rt,
    utils::byte_read::read_ne_value_at,
};

#[cfg(test)]
pub(crate) const NLMSG_HDR_LEN: usize = builtin::Nlmsghdr::len();
pub(crate) const CN_MSG_LEN: usize = 20;
pub(crate) const PROC_EVENT_HEADER_LEN: usize = 16;
pub(crate) const PROC_EVENT_EXEC_PID_OFFSET: usize = 16;
pub(crate) const PROC_EVENT_FORK_CHILD_PID_OFFSET: usize = 24;
const PROC_CONNECTOR_OPEN_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ProcEventSocket {
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
        let Some(recv) = recv_with_timeout(timeout, self.event_sock.recv()).await? else {
            return Ok(None);
        };

        let (meta, payload) = recv;
        Self::parse_pid_event_message(meta.message_type, payload)
    }

    #[cfg(test)]
    fn connector_payload(frame: &[u8]) -> Option<&[u8]> {
        // NOTE(netlink-baseline): connector event frames still require explicit
        // cn_msg offset/length extraction because current generated bindings do
        // not expose a typed cn_msg/proc_event decoder for this payload shape.
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

    fn parse_pid_event_message(msg_type: u16, payload: &[u8]) -> Result<Option<ProcPidEvent>> {
        if !should_process_nlmsg_payload(msg_type, payload)? {
            return Ok(None);
        }

        Ok(Self::parse_pid_event_from_payload(payload))
    }

    fn parse_pid_event_payload(payload: &[u8]) -> Option<ProcPidEvent> {
        let what = read_ne_value_at(payload, 0, u32::from_ne_bytes)?;

        match what {
            x if x == libc::PROC_EVENT_EXEC as u32 || x == libc::PROC_EVENT_EXIT as u32 => {
                let pid =
                    read_ne_value_at(payload, PROC_EVENT_EXEC_PID_OFFSET, u32::from_ne_bytes)?;
                let kind = if what == libc::PROC_EVENT_EXEC as u32 {
                    ProcEventKind::Exec
                } else {
                    ProcEventKind::Exit
                };
                Some(ProcPidEvent { pid, kind })
            }
            x if x == libc::PROC_EVENT_FORK as u32 => {
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

    #[cfg(test)]
    fn run_netlink_future<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::new)?
            .block_on(future)
    }

    fn switch_to_host_netns() -> Result<()> {
        let host_netns = std::fs::File::open("/proc/1/ns/net")?;
        move_into_link_name_space(host_netns.as_fd(), Some(LinkNameSpaceType::Network))?;
        Ok(())
    }

    fn build_listen_payload() -> [u8; CN_MSG_LEN + 4] {
        let mut msg = [0_u8; CN_MSG_LEN + 4];

        // cn_msg
        msg[0..4].copy_from_slice(&(libc::CN_IDX_PROC as u32).to_ne_bytes());
        msg[4..8].copy_from_slice(&(libc::CN_VAL_PROC as u32).to_ne_bytes());
        msg[8..12].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[12..16].copy_from_slice(&(0_u32).to_ne_bytes());
        msg[16..18].copy_from_slice(&(4_u16).to_ne_bytes());
        msg[18..20].copy_from_slice(&(0_u16).to_ne_bytes());

        // proc_cn_mcast_op
        msg[20..24].copy_from_slice(&(libc::PROC_CN_MCAST_LISTEN as u32).to_ne_bytes());

        msg
    }

    pub fn open() -> Result<Self> {
        run_on_netlink_rt(Self::open_async())
    }

    pub async fn open_async() -> Result<Self> {
        let _ = Self::switch_to_host_netns();

        let mut request_sock = crate::platform::netlink::io::new_request_socket();
        let event_sock =
            open_and_listen_multicast_socket(libc::NETLINK_CONNECTOR as u16, libc::CN_IDX_PROC as u32)?;

        let request = ProcListenRequest {
            payload: Self::build_listen_payload(),
        };
        request_with_ack_timeout(
            &mut request_sock,
            &request,
            PROC_CONNECTOR_OPEN_TIMEOUT,
            "proc connector request timed out",
            "proc connector ack timed out",
        )
        .await?;

        Ok(Self { event_sock })
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

    #[cfg(test)]
    pub(crate) fn probe_parse_pid_event_message(
        msg_type: u16,
        payload: &[u8],
    ) -> Result<Option<ProcPidEvent>> {
        Self::parse_pid_event_message(msg_type, payload)
    }
}

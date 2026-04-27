use std::{os::fd::AsFd, time::Duration};

use anyhow::Result;
use nix::libc;
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

#[cfg(test)]
pub(crate) use crate::platform::netlink::wire::NLMSG_HDR_LEN;
use crate::{
    platform::netlink::io::{
        MulticastSocketRaw, NetlinkRequest, Protocol, open_and_listen_multicast_socket,
        recv_with_timeout, request_with_ack_timeout,
    },
    platform::netlink::message::NetlinkEvent,
    platform::netlink::runtime::run_on_netlink_rt,
    platform::procmon::proc_event::{ProcEventKind, ProcPidEvent},
};

#[cfg(test)]
pub(crate) const CN_MSG_LEN: usize = std::mem::size_of::<CnMsg>();
pub(crate) const PROC_EVENT_HEADER_LEN: usize = std::mem::size_of::<ProcEventHeader>();
/// Offset of `process_pid` from start of proc_event (after header).
#[cfg(test)]
pub(crate) const PROC_EVENT_EXEC_PID_OFFSET: usize = PROC_EVENT_HEADER_LEN;
/// Offset of `child_pid` from start of proc_event (header + parent_pid + parent_tgid).
#[cfg(test)]
pub(crate) const PROC_EVENT_FORK_CHILD_PID_OFFSET: usize = PROC_EVENT_HEADER_LEN + 8;
const PROC_CONNECTOR_OPEN_TIMEOUT: Duration = Duration::from_secs(2);

/// Kernel `struct cb_id` + `struct cn_msg` header (20 bytes).
/// NOTE(netlink-baseline): no typed cn_msg in netlink-bindings; hand-defined
/// to match `<linux/connector.h>`.
#[repr(C)]
#[derive(Clone, Copy)]
struct CnMsg {
    id_idx: u32,
    id_val: u32,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}

/// Kernel `struct proc_event` common header (16 bytes):
/// `what` discriminant + `cpu` + `timestamp_ns`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcEventHeader {
    what: u32,
    _cpu: u32,
    _timestamp_ns: u64,
}

/// Kernel `struct exec_proc_event` / `struct exit_proc_event` prefix:
/// `process_pid` + `process_tgid` (8 bytes at header offset 0).
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecExitProcEventData {
    process_pid: u32,
    _process_tgid: u32,
}

/// Kernel `struct fork_proc_event`: parent pid/tgid + child pid/tgid.
#[repr(C)]
#[derive(Clone, Copy)]
struct ForkProcEventData {
    _parent_pid: u32,
    _parent_tgid: u32,
    child_pid: u32,
    _child_tgid: u32,
}

/// Listen/ignore payload: `CnMsg` header + `enum proc_cn_mcast_op` (4 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct CnMsgListenPayload {
    cn: CnMsg,
    op: u32,
}

pub struct ProcEventSocket {
    pub(crate) event_sock: MulticastSocketRaw,
}

impl NetlinkEvent for ProcPidEvent {
    fn decode_event(_msg_type: u16, payload: &[u8]) -> Result<Option<Self>> {
        Ok(ProcEventSocket::parse_pid_event_from_payload(payload))
    }
}

struct ProcListenRequest {
    payload: [u8; std::mem::size_of::<CnMsgListenPayload>()],
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
        ProcPidEvent::decode_from_raw(meta.message_type, payload)
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
        // SAFETY: CnMsg is #[repr(C)] and we verified the frame is large
        // enough above. read_unaligned handles arbitrary frame alignment.
        let cn: CnMsg =
            unsafe { std::ptr::read_unaligned(frame[NLMSG_HDR_LEN..].as_ptr() as *const CnMsg) };
        let cn_msg_data_len = cn.len as usize;
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
        ProcPidEvent::decode_from_raw(msg_type, payload)
    }

    fn parse_pid_event_payload(payload: &[u8]) -> Option<ProcPidEvent> {
        if payload.len() < PROC_EVENT_HEADER_LEN {
            return None;
        }
        // SAFETY: ProcEventHeader is #[repr(C)], 16 bytes, and we verified
        // length above. read_unaligned handles any alignment.
        let hdr: ProcEventHeader =
            unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const ProcEventHeader) };
        let event_data = &payload[PROC_EVENT_HEADER_LEN..];

        match hdr.what {
            x if x == libc::PROC_EVENT_EXEC as u32 || x == libc::PROC_EVENT_EXIT as u32 => {
                if event_data.len() < std::mem::size_of::<ExecExitProcEventData>() {
                    return None;
                }
                let data: ExecExitProcEventData = unsafe {
                    std::ptr::read_unaligned(event_data.as_ptr() as *const ExecExitProcEventData)
                };
                let kind = if x == libc::PROC_EVENT_EXEC as u32 {
                    ProcEventKind::Exec
                } else {
                    ProcEventKind::Exit
                };
                Some(ProcPidEvent {
                    pid: data.process_pid,
                    kind,
                })
            }
            x if x == libc::PROC_EVENT_FORK as u32 => {
                if event_data.len() < std::mem::size_of::<ForkProcEventData>() {
                    return None;
                }
                let data: ForkProcEventData = unsafe {
                    std::ptr::read_unaligned(event_data.as_ptr() as *const ForkProcEventData)
                };
                Some(ProcPidEvent {
                    pid: data.child_pid,
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

    fn build_listen_payload() -> [u8; std::mem::size_of::<CnMsgListenPayload>()] {
        let msg = CnMsgListenPayload {
            cn: CnMsg {
                id_idx: libc::CN_IDX_PROC as u32,
                id_val: libc::CN_VAL_PROC as u32,
                seq: 0,
                ack: 0,
                len: 4,
                flags: 0,
            },
            op: libc::PROC_CN_MCAST_LISTEN as u32,
        };
        // SAFETY: CnMsgListenPayload is #[repr(C)] with no padding on all
        // Linux targets (all fields are naturally aligned).
        unsafe { std::mem::transmute(msg) }
    }

    pub fn open() -> Result<Self> {
        run_on_netlink_rt(Self::open_async())
    }

    pub async fn open_async() -> Result<Self> {
        let _ = Self::switch_to_host_netns();

        let mut request_sock = crate::platform::netlink::io::new_request_socket();
        let event_sock = open_and_listen_multicast_socket(
            libc::NETLINK_CONNECTOR as u16,
            libc::CN_IDX_PROC as u32,
        )?;

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

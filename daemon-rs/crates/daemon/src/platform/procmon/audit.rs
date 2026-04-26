use std::time::Duration;

use anyhow::{Result, bail};
use netlink_bindings::builtin;
use netlink_bindings::traits::{NetlinkRequest, Protocol};
use netlink_socket2::MulticastSocketRaw;
use nix::libc;

use crate::platform::netlink::{
    control::should_process_nlmsg_payload,
    io::{new_request_socket, open_multicast_socket, recv_with_timeout, request_with_ack_timeout},
};

#[cfg(test)]
const NLMSG_HDR_LEN: usize = builtin::Nlmsghdr::len();
const STATUS_MESSAGE_LEN: usize = 40;

const AUDIT_SET: u16 = 1001;
const AUDIT_EVENT_MESSAGE_MIN: u16 = 1300;
const AUDIT_EVENT_MESSAGE_MAX: u16 = 1399;

const AUDIT_STATUS_ENABLED: u32 = 1;
const AUDIT_STATUS_PID: u32 = 4;
const AUDIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditEventMessage {
    pub(crate) kind: u16,
    pub(crate) data: String,
}

pub(crate) struct AuditNetlinkSocket {
    request_sock: netlink_socket2::NetlinkSocket,
    event_sock: MulticastSocketRaw,
}

struct AuditSetRequest {
    payload: [u8; STATUS_MESSAGE_LEN],
}

impl NetlinkRequest for AuditSetRequest {
    fn protocol(&self) -> Protocol {
        Protocol::Raw {
            protonum: libc::NETLINK_AUDIT as u16,
            request_type: AUDIT_SET,
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

impl AuditNetlinkSocket {
    pub(crate) fn open() -> Result<Self> {
        let request_sock = new_request_socket();
        let event_sock = open_multicast_socket(libc::NETLINK_AUDIT as u16)?;

        Ok(Self {
            request_sock,
            event_sock,
        })
    }

    pub(crate) async fn enable_events(&mut self) -> Result<()> {
        let request = AuditSetRequest {
            payload: Self::build_enable_events_payload(),
        };
        request_with_ack_timeout(
            &mut self.request_sock,
            &request,
            AUDIT_REQUEST_TIMEOUT,
            "audit request timed out",
            "audit ack timed out",
        )
        .await
    }

    pub(crate) async fn recv_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<AuditEventMessage>> {
        let Some(recv) = recv_with_timeout(timeout, self.event_sock.recv()).await? else {
            return Ok(None);
        };

        let (meta, payload) = recv;
        Self::parse_event_message(meta.message_type, payload)
    }

    fn build_enable_events_payload() -> [u8; STATUS_MESSAGE_LEN] {
        let mut payload = [0_u8; STATUS_MESSAGE_LEN];
        payload[0..4].copy_from_slice(&(AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID).to_ne_bytes());
        payload[4..8].copy_from_slice(&1_u32.to_ne_bytes());
        payload[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
        payload
    }

    fn parse_event_message(msg_type: u16, payload: &[u8]) -> Result<Option<AuditEventMessage>> {
        if !should_process_nlmsg_payload(msg_type, payload)? {
            return Ok(None);
        }

        if (AUDIT_EVENT_MESSAGE_MIN..=AUDIT_EVENT_MESSAGE_MAX).contains(&msg_type) {
            let data = String::from_utf8_lossy(payload)
                .trim_end_matches('\0')
                .to_owned();
            return Ok(Some(AuditEventMessage {
                kind: msg_type,
                data,
            }));
        }

        Ok(None)
    }

    /// Parse a framed audit datagram containing one or more netlink messages.
    /// Used by tests that construct full datagram payloads.
    #[cfg(test)]
    fn parse_event_datagram(datagram: &[u8]) -> Result<Option<AuditEventMessage>> {
        let mut offset = 0_usize;
        while offset + NLMSG_HDR_LEN <= datagram.len() {
            let (msg_len, msg_type) = {
                let hdr = &datagram[offset..];
                if hdr.len() < NLMSG_HDR_LEN {
                    break;
                }
                let len = u32::from_ne_bytes(hdr[0..4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(hdr[4..6].try_into().unwrap());
                let normalized = if len == 0 {
                    0
                } else if datagram.len() - offset >= len
                    && (datagram.len() - offset).saturating_sub(len) <= NLMSG_HDR_LEN
                {
                    datagram.len() - offset
                } else {
                    len
                };
                (normalized, mtype)
            };
            if msg_len < NLMSG_HDR_LEN || offset + msg_len > datagram.len() {
                bail!("audit event packet has invalid message length");
            }

            let payload = &datagram[(offset + NLMSG_HDR_LEN)..(offset + msg_len)];
            if let Some(event) = Self::parse_event_message(msg_type, payload)? {
                return Ok(Some(event));
            }

            offset += (msg_len + 3) & !3;
        }

        Ok(None)
    }

    #[cfg(test)]
    pub(crate) fn probe_build_enable_events_payload() -> [u8; STATUS_MESSAGE_LEN] {
        Self::build_enable_events_payload()
    }

    #[cfg(test)]
    pub(crate) fn probe_parse_event_datagram(datagram: &[u8]) -> Result<Option<AuditEventMessage>> {
        Self::parse_event_datagram(datagram)
    }

    #[cfg(test)]
    pub(crate) fn probe_parse_event_message(
        msg_type: u16,
        payload: &[u8],
    ) -> Result<Option<AuditEventMessage>> {
        Self::parse_event_message(msg_type, payload)
    }
}

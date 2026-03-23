use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use nix::libc;
use netlink_bindings::traits::{NetlinkRequest, Protocol};
use netlink_socket2::{MulticastSocketRaw, NetlinkSocket};

const NLMSG_HDR_LEN: usize = 16;
const STATUS_MESSAGE_LEN: usize = 40;

const AUDIT_SET: u16 = 1001;
const AUDIT_EVENT_MESSAGE_MIN: u16 = 1300;
const AUDIT_EVENT_MESSAGE_MAX: u16 = 1399;

const AUDIT_STATUS_ENABLED: u32 = 1;
const AUDIT_STATUS_PID: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditEventMessage {
    pub(crate) kind: u16,
    pub(crate) data: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetlinkHeader {
    len: u32,
    msg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

pub(crate) struct AuditNetlinkSocket {
    request_sock: NetlinkSocket,
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
        let request_sock = NetlinkSocket::new();
        let event_sock = MulticastSocketRaw::new(libc::NETLINK_AUDIT as u16)?;

        Ok(Self {
            request_sock,
            event_sock,
        })
    }

    pub(crate) async fn enable_events(&mut self) -> Result<()> {
        let request = AuditSetRequest {
            payload: Self::build_enable_events_payload(),
        };
        let mut iter = self.request_sock.request(&request).await?;
        iter.recv_ack().await.map_err(anyhow::Error::new)
    }

    pub(crate) async fn recv_event(&mut self, timeout: Duration) -> Result<Option<AuditEventMessage>> {
        let recv = match tokio::time::timeout(timeout, self.event_sock.recv()).await {
            Ok(Ok(recv)) => recv,
            Ok(Err(err)) => return Err(anyhow::Error::new(err)),
            Err(_) => return Ok(None),
        };

        let (meta, payload) = recv;
        let datagram = Self::build_datagram(meta.message_type, payload);
        Self::parse_event_datagram(&datagram)
    }

    fn build_enable_events_payload() -> [u8; STATUS_MESSAGE_LEN] {
        let mut payload = [0_u8; STATUS_MESSAGE_LEN];
        payload[0..4].copy_from_slice(&(AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID).to_ne_bytes());
        payload[4..8].copy_from_slice(&1_u32.to_ne_bytes());
        payload[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
        payload
    }

    fn build_datagram(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = NLMSG_HDR_LEN + payload.len();
        let mut out = Vec::with_capacity(total_len);
        out.extend((total_len as u32).to_ne_bytes());
        out.extend(msg_type.to_ne_bytes());
        out.extend(0_u16.to_ne_bytes());
        out.extend(0_u32.to_ne_bytes());
        out.extend(0_u32.to_ne_bytes());
        out.extend(payload);
        out
    }

    fn parse_event_datagram(datagram: &[u8]) -> Result<Option<AuditEventMessage>> {
        let mut offset = 0_usize;
        while offset + NLMSG_HDR_LEN <= datagram.len() {
            let header = Self::parse_header(&datagram[offset..])
                .ok_or_else(|| anyhow!("audit event packet too short for header"))?;
            let msg_len = Self::normalized_msg_len(header.len as usize, datagram.len() - offset);
            if msg_len < NLMSG_HDR_LEN || offset + msg_len > datagram.len() {
                bail!("audit event packet has invalid message length");
            }

            if (AUDIT_EVENT_MESSAGE_MIN..=AUDIT_EVENT_MESSAGE_MAX).contains(&header.msg_type) {
                let payload = &datagram[(offset + NLMSG_HDR_LEN)..(offset + msg_len)];
                let data = String::from_utf8_lossy(payload)
                    .trim_end_matches('\0')
                    .to_string();
                return Ok(Some(AuditEventMessage {
                    kind: header.msg_type,
                    data,
                }));
            }

            if header.msg_type == libc::NLMSG_ERROR as u16 {
                let payload = &datagram[(offset + NLMSG_HDR_LEN)..(offset + msg_len)];
                if payload.len() >= 4 {
                    let code = i32::from_ne_bytes(payload[0..4].try_into().expect("fixed-size slice"));
                    if code != 0 {
                        let err = std::io::Error::from_raw_os_error((-code).max(1));
                        return Err(err.into());
                    }
                }
            }

            offset += Self::align_len(msg_len);
        }

        Ok(None)
    }

    fn parse_header(buf: &[u8]) -> Option<NetlinkHeader> {
        if buf.len() < NLMSG_HDR_LEN {
            return None;
        }

        Some(NetlinkHeader {
            len: u32::from_ne_bytes(buf[0..4].try_into().ok()?),
            msg_type: u16::from_ne_bytes(buf[4..6].try_into().ok()?),
            flags: u16::from_ne_bytes(buf[6..8].try_into().ok()?),
            seq: u32::from_ne_bytes(buf[8..12].try_into().ok()?),
            pid: u32::from_ne_bytes(buf[12..16].try_into().ok()?),
        })
    }

    fn normalized_msg_len(declared_len: usize, remaining_len: usize) -> usize {
        if declared_len == 0 {
            return 0;
        }

        if remaining_len >= declared_len && remaining_len.saturating_sub(declared_len) <= NLMSG_HDR_LEN {
            return remaining_len;
        }

        declared_len
    }

    fn align_len(len: usize) -> usize {
        (len + 3) & !3
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_build_enable_events_payload() -> [u8; STATUS_MESSAGE_LEN] {
        Self::build_enable_events_payload()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_event_datagram(datagram: &[u8]) -> Result<Option<AuditEventMessage>> {
        Self::parse_event_datagram(datagram)
    }
}
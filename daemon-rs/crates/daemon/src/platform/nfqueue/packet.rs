use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nix::libc;

use crate::models::connection::state::{ConnectionAttempt, TransportProtocol};

use super::state::RejectSocketSpec;

pub(crate) struct NfqueuePacketParser;

impl NfqueuePacketParser {
    pub(crate) fn parse_dns_answer_mappings(payload: &[u8]) -> Vec<(IpAddr, String)> {
        let Some((udp_offset, src_port, _dst_port)) = Self::udp_offsets(payload) else {
            return Vec::new();
        };
        if src_port != 53 {
            return Vec::new();
        }
        if payload.len() < udp_offset + 8 {
            return Vec::new();
        }

        let dns = &payload[udp_offset + 8..];
        if dns.len() < 12 {
            return Vec::new();
        }

        let qdcount = u16::from_be_bytes([dns[4], dns[5]]) as usize;
        let ancount = u16::from_be_bytes([dns[6], dns[7]]) as usize;
        let mut pos = 12_usize;

        let mut question_name = String::new();
        for _ in 0..qdcount {
            let Some((name, next)) = Self::parse_dns_name(dns, pos) else {
                return Vec::new();
            };
            question_name = name;
            if dns.len() < next + 4 {
                return Vec::new();
            }
            pos = next + 4;
        }

        let mut out = Vec::new();
        for _ in 0..ancount {
            let Some((_answer_name, next)) = Self::parse_dns_name(dns, pos) else {
                break;
            };
            if dns.len() < next + 10 {
                break;
            }
            let rtype = u16::from_be_bytes([dns[next], dns[next + 1]]);
            let rdlen = u16::from_be_bytes([dns[next + 8], dns[next + 9]]) as usize;
            let rdata_off = next + 10;
            if dns.len() < rdata_off + rdlen {
                break;
            }

            match rtype {
                1 if rdlen == 4 => {
                    let ip = Ipv4Addr::new(
                        dns[rdata_off],
                        dns[rdata_off + 1],
                        dns[rdata_off + 2],
                        dns[rdata_off + 3],
                    );
                    if !question_name.is_empty() {
                        out.push((IpAddr::V4(ip), question_name.clone()));
                    }
                }
                28 if rdlen == 16 => {
                    if let Ok(octets) = <[u8; 16]>::try_from(&dns[rdata_off..rdata_off + 16]) {
                        if !question_name.is_empty() {
                            out.push((IpAddr::V6(Ipv6Addr::from(octets)), question_name.clone()));
                        }
                    }
                }
                5 => {
                    // CNAME aliases are handled by the DNS worker, not nfqueue
                }
                _ => {}
            }

            pos = rdata_off + rdlen;
        }

        out
    }

    pub(crate) fn parse_dns_last_question(payload: &[u8]) -> Option<String> {
        if let Some((udp_offset, _src_port, dst_port)) = Self::udp_offsets(payload)
            && dst_port == 53
            && payload.len() >= udp_offset + 8
        {
            return Self::parse_dns_last_question_name(&payload[udp_offset + 8..]);
        }

        if let Some((tcp_offset, _src_port, dst_port, tcp_header_len)) = Self::tcp_offsets(payload)
            && dst_port == 53
        {
            let dns_off = tcp_offset + tcp_header_len;
            if payload.len() >= dns_off + 2 {
                let declared_len =
                    u16::from_be_bytes([payload[dns_off], payload[dns_off + 1]]) as usize;
                let dns_start = dns_off + 2;
                let dns_end = dns_start.saturating_add(declared_len).min(payload.len());
                if dns_end > dns_start {
                    return Self::parse_dns_last_question_name(&payload[dns_start..dns_end]);
                }
            }
        }

        None
    }

    pub(crate) fn parse_connection_attempt(
        request_id: u64,
        payload: &[u8],
        uid: u32,
        iface_in_idx: u32,
        iface_out_idx: u32,
    ) -> Option<ConnectionAttempt> {
        if payload.is_empty() {
            return None;
        }

        let version = payload[0] >> 4;
        match version {
            4 => Self::parse_ipv4_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx),
            6 => Self::parse_ipv6_attempt(request_id, payload, uid, iface_in_idx, iface_out_idx),
            _ => None,
        }
    }

    pub(super) fn build_reject_socket_spec(
        attempt: &ConnectionAttempt,
    ) -> Option<RejectSocketSpec> {
        let family = Self::infer_family(attempt);
        let ipproto = Self::protocol_to_ipproto(attempt.protocol)?;
        Some(RejectSocketSpec {
            family,
            ipproto,
            src: attempt.src_addr,
            src_port: attempt.src_port,
            dst: attempt.dst_addr,
            dst_port: attempt.dst_port,
        })
    }

    fn infer_family(attempt: &ConnectionAttempt) -> u8 {
        match attempt.src_addr {
            IpAddr::V6(_) => libc::AF_INET6 as u8,
            IpAddr::V4(_) => libc::AF_INET as u8,
        }
    }

    fn protocol_to_ipproto(protocol: TransportProtocol) -> Option<u8> {
        match protocol {
            TransportProtocol::Tcp => Some(libc::IPPROTO_TCP as u8),
            TransportProtocol::Udp => Some(libc::IPPROTO_UDP as u8),
            TransportProtocol::UdpLite => Some(136_u8),
            TransportProtocol::Sctp => Some(132_u8),
            TransportProtocol::Icmp => None,
        }
    }

    fn parse_dns_last_question_name(dns: &[u8]) -> Option<String> {
        if dns.len() < 12 {
            return None;
        }

        let qdcount = u16::from_be_bytes([dns[4], dns[5]]) as usize;
        let mut pos = 12_usize;
        let mut last = None;

        for _ in 0..qdcount {
            let Some((name, next)) = Self::parse_dns_name(dns, pos) else {
                break;
            };
            if dns.len() < next + 4 {
                break;
            }
            if !name.is_empty() {
                // Normalise to lower-case: DNS names are case-insensitive
                // (RFC 4343) and all downstream comparisons expect lower-case.
                last = Some(name.to_lowercase());
            }
            pos = next + 4;
        }

        last
    }

    fn tcp_offsets(payload: &[u8]) -> Option<(usize, u16, u16, usize)> {
        if payload.is_empty() {
            return None;
        }

        let version = payload[0] >> 4;
        match version {
            4 => {
                if payload.len() < 20 {
                    return None;
                }
                let ihl = ((payload[0] & 0x0f) as usize) * 4;
                if payload.len() < ihl + 20 || payload[9] != 6 {
                    return None;
                }

                let data_off = ((payload[ihl + 12] >> 4) as usize) * 4;
                if data_off < 20 || payload.len() < ihl + data_off {
                    return None;
                }

                let src = u16::from_be_bytes([payload[ihl], payload[ihl + 1]]);
                let dst = u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]);
                Some((ihl, src, dst, data_off))
            }
            6 => {
                if payload.len() < 60 || payload[6] != 6 {
                    return None;
                }
                let off = 40;

                let data_off = ((payload[off + 12] >> 4) as usize) * 4;
                if data_off < 20 || payload.len() < off + data_off {
                    return None;
                }

                let src = u16::from_be_bytes([payload[off], payload[off + 1]]);
                let dst = u16::from_be_bytes([payload[off + 2], payload[off + 3]]);
                Some((off, src, dst, data_off))
            }
            _ => None,
        }
    }

    fn udp_offsets(payload: &[u8]) -> Option<(usize, u16, u16)> {
        if payload.is_empty() {
            return None;
        }
        let version = payload[0] >> 4;
        match version {
            4 => {
                if payload.len() < 20 {
                    return None;
                }
                let ihl = ((payload[0] & 0x0f) as usize) * 4;
                if payload.len() < ihl + 4 || payload[9] != 17 {
                    return None;
                }
                let src = u16::from_be_bytes([payload[ihl], payload[ihl + 1]]);
                let dst = u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]);
                Some((ihl, src, dst))
            }
            6 => {
                if payload.len() < 44 || payload[6] != 17 {
                    return None;
                }
                let off = 40;
                let src = u16::from_be_bytes([payload[off], payload[off + 1]]);
                let dst = u16::from_be_bytes([payload[off + 2], payload[off + 3]]);
                Some((off, src, dst))
            }
            _ => None,
        }
    }

    fn parse_dns_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut jump_return = 0;
        let mut depth = 0;

        loop {
            if pos >= buf.len() || depth > 32 {
                return None;
            }
            depth += 1;
            let len = buf[pos];
            if len == 0 {
                let next = if jumped { jump_return } else { pos + 1 };
                return Some((labels.join("."), next));
            }
            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= buf.len() {
                    return None;
                }
                let ptr = (((len as u16 & 0x3F) << 8) | buf[pos + 1] as u16) as usize;
                if !jumped {
                    jump_return = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                continue;
            }

            let l = len as usize;
            if pos + 1 + l > buf.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&buf[pos + 1..pos + 1 + l]).to_string());
            pos += 1 + l;
        }
    }

    fn parse_ipv4_attempt(
        request_id: u64,
        payload: &[u8],
        uid: u32,
        iface_in_idx: u32,
        iface_out_idx: u32,
    ) -> Option<ConnectionAttempt> {
        if payload.len() < 20 {
            return None;
        }

        let ihl = ((payload[0] & 0x0f) as usize) * 4;
        if payload.len() < ihl + 4 {
            return None;
        }

        let protocol = match payload[9] {
            1 => TransportProtocol::Icmp,
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            132 => TransportProtocol::Sctp,
            136 => TransportProtocol::UdpLite,
            _ => return None,
        };

        let src_addr = IpAddr::V4(Ipv4Addr::new(
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ));
        let dst_addr = IpAddr::V4(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ));

        let (src_port, dst_port) = match protocol {
            TransportProtocol::Icmp => (0, 0),
            _ => {
                if payload.len() < ihl + 4 {
                    return None;
                }
                (
                    u16::from_be_bytes([payload[ihl], payload[ihl + 1]]),
                    u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]),
                )
            }
        };

        Some(ConnectionAttempt {
            request_id,
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            iface_in_idx,
            iface_out_idx,
            dns_query: None,
            pid: 0,
            uid,
        })
    }

    fn parse_ipv6_attempt(
        request_id: u64,
        payload: &[u8],
        uid: u32,
        iface_in_idx: u32,
        iface_out_idx: u32,
    ) -> Option<ConnectionAttempt> {
        if payload.len() < 44 {
            return None;
        }

        let protocol = match payload[6] {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            58 => TransportProtocol::Icmp,
            132 => TransportProtocol::Sctp,
            136 => TransportProtocol::UdpLite,
            _ => return None,
        };

        let src_addr = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[8..24]).ok()?));
        let dst_addr = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[24..40]).ok()?));

        let (src_port, dst_port) = match protocol {
            TransportProtocol::Icmp => (0, 0),
            _ => {
                if payload.len() < 44 {
                    return None;
                }
                (
                    u16::from_be_bytes([payload[40], payload[41]]),
                    u16::from_be_bytes([payload[42], payload[43]]),
                )
            }
        };

        Some(ConnectionAttempt {
            request_id,
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            iface_in_idx,
            iface_out_idx,
            dns_query: None,
            pid: 0,
            uid,
        })
    }
}

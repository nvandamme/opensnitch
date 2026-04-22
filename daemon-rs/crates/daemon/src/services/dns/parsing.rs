use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use crate::models::dns_payload::DnsPayload;
use crate::utils::byte_read::read_ne_value_at;
use crate::utils::name_parsing::normalized_name;
use crate::utils::nul_terminated::nul_terminated_utf8_lossy;

use super::{DnsEbpfEventDeduper, DnsService};

pub(crate) fn normalize_dns_host(raw: &str) -> Option<String> {
    let normalized = normalized_name(raw);
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty() {
        return None;
    }
    Some(normalized.to_string())
}

impl DnsService {
    pub(crate) fn parse_ebpf_dns_sample(sample: &[u8]) -> Option<DnsPayload> {
        if sample.len() != Self::EBPF_DNS_EVENT_LEN {
            return None;
        }

        let addr_type = read_ne_value_at(sample, 0, u32::from_ne_bytes)?;
        if addr_type != 2 && addr_type != 10 {
            return None;
        }

        let ip_bytes = sample.get(4..20)?;
        let host_bytes = sample.get(20..272)?;
        let host = nul_terminated_utf8_lossy(host_bytes);
        let host = normalize_dns_host(&host)?;

        let ip = if addr_type == 2 {
            IpAddr::V4(Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
        } else {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(ip_bytes);
            IpAddr::V6(Ipv6Addr::from(octets))
        };

        Some(DnsPayload::answer(host, ip))
    }
}

impl DnsEbpfEventDeduper {
    pub(crate) fn should_emit(&mut self, payload: &DnsPayload) -> bool {
        match payload {
            DnsPayload::Answers(record) => record
                .addresses
                .first()
                .is_some_and(|ip| {
                    Self::should_emit_at(
                        &mut self.recent_events,
                        &ip.to_string(),
                        record.host.as_ref(),
                        Instant::now(),
                    )
                }),
            DnsPayload::Alias { alias, host } => Self::should_emit_at(
                &mut self.recent_events,
                alias.as_ref(),
                host.as_ref(),
                Instant::now(),
            ),
        }
    }

    pub(crate) fn should_emit_at(
        recent_events: &mut HashMap<(String, String), Instant>,
        ip: &str,
        host: &str,
        now: Instant,
    ) -> bool {
        const DEDUP_WINDOW: Duration = Duration::from_secs(5);
        const MAX_RECENT_EVENTS: usize = 4096;

        recent_events.retain(|_, seen_at| now.duration_since(*seen_at) <= DEDUP_WINDOW);

        if recent_events.len() > MAX_RECENT_EVENTS {
            recent_events.clear();
        }

        let key = (ip.to_string(), host.to_string());
        if let Some(seen_at) = recent_events.get(&key)
            && now.duration_since(*seen_at) <= DEDUP_WINDOW
        {
            return false;
        }

        recent_events.insert(key, now);
        true
    }
}

use std::{
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
};

use crate::models::dns::payload::DnsAnswerRecord;

use super::{DNS_CACHE_CAPACITY, DnsCacheMutation, DnsService};

impl DnsService {
    pub(crate) fn configure_cache_capacity(capacity: usize) {
        DNS_CACHE_CAPACITY.store(capacity.max(1), Ordering::Relaxed);
    }

    pub async fn track_answers(&self, record: DnsAnswerRecord) -> DnsCacheMutation {
        let entries = record
            .addresses
            .iter()
            .copied()
            .filter(|ip| !ip.is_loopback())
            .map(|ip| (ip, Arc::clone(&record.host)))
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return DnsCacheMutation::default();
        }

        let evicted = self
            .ip_lookup
            .insert_many_with_eviction_count(entries.clone());
        DnsCacheMutation {
            entries: entries.len().min(u32::MAX as usize) as u32,
            evicted,
        }
    }

    pub async fn track_alias(
        &self,
        alias: impl Into<Arc<str>>,
        host: impl Into<Arc<str>>,
    ) -> DnsCacheMutation {
        let alias = alias.into();
        let host = host.into();
        if alias == host {
            return DnsCacheMutation::default();
        }

        let evicted = self.alias_lookup.insert_with_eviction_count(alias, host);
        DnsCacheMutation {
            entries: 1,
            evicted,
        }
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<Arc<str>> {
        let mut host = self.ip_lookup.get(&ip)?;
        // Follow alias chain with a bounded hop limit instead of a per-lookup heap
        // HashSet. Real DNS alias chains are ≤ 3 hops; the limit guards against any
        // injected cycle without allocating.
        for _ in 0..8 {
            let Some(next) = self.alias_lookup.get(&host) else {
                break;
            };
            host = next;
        }
        Some(host)
    }
}

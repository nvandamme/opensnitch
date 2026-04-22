use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::Ordering,
    },
};

use crate::models::dns_payload::DnsAnswerRecord;

use super::{DNS_CACHE_CAPACITY, DnsService};

impl DnsService {
    pub(crate) fn configure_cache_capacity(capacity: usize) {
        DNS_CACHE_CAPACITY.store(capacity.max(1), Ordering::Relaxed);
    }

    pub async fn track_answers(&self, record: DnsAnswerRecord) {
        let entries = record
            .addresses
            .iter()
            .copied()
            .filter(|ip| !ip.is_loopback())
            .map(|ip| (ip, Arc::clone(&record.host)))
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return;
        }

        self.ip_lookup.insert_many(entries);
    }

    pub async fn track_alias(&self, alias: impl Into<Arc<str>>, host: impl Into<Arc<str>>) {
        let alias = alias.into();
        let host = host.into();
        if alias == host {
            return;
        }

        self.alias_lookup.insert(alias, host);
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<Arc<str>> {
        let mut host = self.ip_lookup.get(&ip)?;
        // Follow alias chain with a bounded hop limit instead of a per-lookup heap
        // HashSet. Real DNS alias chains are ≤ 3 hops; the limit guards against any
        // injected cycle without allocating.
        for _ in 0..8 {
            let Some(next) = self.alias_lookup.get(&host) else { break };
            host = next;
        }
        Some(host)
    }
}

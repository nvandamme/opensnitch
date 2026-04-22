use std::sync::atomic::Ordering;

use crate::services::dns::{DNS_CACHE_CAPACITY, DnsService};

impl DnsService {
    pub(crate) async fn probe_cache_len(&self) -> usize {
        self.ip_lookup.len() + self.alias_lookup.len()
    }

    pub(crate) fn probe_cache_capacity() -> usize {
        DNS_CACHE_CAPACITY.load(Ordering::Relaxed)
    }
}

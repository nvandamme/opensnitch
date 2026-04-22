use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::RwLock;

use crate::utils::lru_cache::LruCache;

#[cfg(not(test))]
const DEFAULT_DNS_CACHE_CAPACITY: usize = 4_000_000;
#[cfg(test)]
const DEFAULT_DNS_CACHE_CAPACITY: usize = 8_192;
static DNS_CACHE_CAPACITY: AtomicUsize = AtomicUsize::new(DEFAULT_DNS_CACHE_CAPACITY);

#[derive(Clone)]
pub struct DnsService {
    ip_cache: Arc<RwLock<LruCache<IpAddr, String>>>,
    alias_cache: Arc<RwLock<LruCache<String, String>>>,
}

impl Default for DnsService {
    fn default() -> Self {
        let capacity = DNS_CACHE_CAPACITY.load(Ordering::Relaxed).max(1);
        Self {
            ip_cache: Arc::new(RwLock::new(LruCache::new(capacity))),
            alias_cache: Arc::new(RwLock::new(LruCache::new(capacity))),
        }
    }
}

impl DnsService {
    pub(crate) fn configure_cache_capacity(capacity: usize) {
        DNS_CACHE_CAPACITY.store(capacity.max(1), Ordering::Relaxed);
    }

    pub async fn track(&self, ip: String, host: String) {
        if ip == host {
            return;
        }

        if let Ok(addr) = ip.parse::<IpAddr>() {
            if addr.is_loopback() {
                return;
            }
            self.ip_cache.write().await.insert(addr, host);
        } else {
            self.alias_cache.write().await.insert(ip, host);
        }
    }

    pub async fn lookup(&self, ip: &str) -> Option<String> {
        let ip = ip.parse::<IpAddr>().ok()?;
        self.lookup_ip(ip).await
    }

    pub async fn lookup_ip(&self, ip: IpAddr) -> Option<String> {
        let mut ip_cache = self.ip_cache.write().await;
        let mut host = ip_cache.get_cloned_by(&ip)?;
        drop(ip_cache);

        let mut alias_cache = self.alias_cache.write().await;
        let mut seen = std::collections::HashSet::new();
        seen.insert(host.clone());

        while let Some(next) = alias_cache.get_cloned_by(host.as_str()) {
            if !seen.insert(next.clone()) {
                break;
            }
            host = next;
        }

        Some(host)
    }

    #[cfg(test)]
    pub(crate) async fn probe_cache_len(&self) -> usize {
        self.ip_cache.read().await.len() + self.alias_cache.read().await.len()
    }

    #[cfg(test)]
    pub(crate) fn probe_cache_capacity() -> usize {
        DNS_CACHE_CAPACITY.load(Ordering::Relaxed)
    }
}

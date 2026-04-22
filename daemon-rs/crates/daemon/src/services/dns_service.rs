use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct DnsService {
    cache: Arc<RwLock<HashMap<String, String>>>,
}

impl DnsService {
    pub async fn track(&self, ip: String, host: String) {
        if ip.starts_with("127.") || ip == "::1" || ip == host {
            return;
        }
        self.cache.write().await.insert(ip, host);
    }

    pub async fn lookup(&self, ip: &str) -> Option<String> {
        let cache = self.cache.read().await;
        let mut host = cache.get(ip).cloned()?;
        let mut seen = std::collections::HashSet::new();
        while let Some(next) = cache.get(&host) {
            if !seen.insert(host.clone()) {
                break;
            }
            host = next.clone();
        }
        Some(host)
    }
}

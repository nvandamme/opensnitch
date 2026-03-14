use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct DnsService {
    cache: Arc<RwLock<HashMap<String, String>>>,
}

impl DnsService {
    pub async fn track(&self, ip: String, host: String) {
        self.cache.write().await.insert(ip, host);
    }

    pub async fn lookup(&self, ip: &str) -> Option<String> {
        self.cache.read().await.get(ip).cloned()
    }
}

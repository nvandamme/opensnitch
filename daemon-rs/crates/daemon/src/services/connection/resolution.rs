use std::collections::HashMap;
use std::sync::Arc;

use crate::models::{
    connection_state::ConnectionAttempt,
    process_state::{ProcessInfo, ProcessNode},
};

use super::{ConnectionContext, ConnectionService};

impl ConnectionService {
    pub(super) async fn resolve_context(&self, attempt: ConnectionAttempt) -> ConnectionContext {
        let mut attempt = attempt;
        if let Some(owner) = self.resolve_owner_by_ebpf_map(
            attempt.protocol,
            attempt.src_addr,
            attempt.src_port,
            attempt.dst_addr,
            attempt.dst_port,
        ) {
            if attempt.uid == 0 {
                attempt.uid = owner.uid;
            }
            if attempt.pid == 0 {
                attempt.pid = owner.pid;
            }
        }

        if attempt.uid == 0 || attempt.pid == 0 {
            attempt = Self::enrich_connection_owner_fallback_async(attempt).await;
        }

        let process = self.resolve_process_info(&attempt).await;

        let mut dst_host: Option<Arc<str>> = if attempt.dst_port == 53 {
            attempt.dns_query.take().map(Arc::from)
        } else {
            None
        };
        if dst_host.is_none() && Self::should_lookup_host(&attempt) {
            dst_host = self.dns.lookup_ip(attempt.dst_addr);
        }

        ConnectionContext {
            attempt,
            process,
            dst_host,
        }
    }

    fn should_lookup_host(attempt: &ConnectionAttempt) -> bool {
        let dst = attempt.dst_addr;
        !(dst.is_loopback() || dst.is_unspecified() || dst.is_multicast())
    }

    async fn resolve_process_info(&self, attempt: &ConnectionAttempt) -> ProcessInfo {
        if attempt.pid == 0 {
            return Self::kernel_process_info();
        }

        match self.process.inspect(attempt.pid).await {
            Ok(info) => info,
            Err(_) => Self::unknown_process_info(attempt.pid),
        }
    }

    fn kernel_process_info() -> ProcessInfo {
        ProcessInfo {
            pid: 0,
            path: "Kernel connection".to_string(),
            args: Vec::new(),
            cwd: None,
            env_preview: Vec::new(),
            env_map: HashMap::new(),
            process_hash: None,
            process_hash_md5: None,
            process_hash_sha1: None,
            parent_chain: vec![ProcessNode {
                pid: 0,
                path: "Kernel connection".to_string(),
            }],
        }
    }

    fn unknown_process_info(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            path: String::new(),
            args: Vec::new(),
            cwd: None,
            env_preview: Vec::new(),
            env_map: HashMap::new(),
            process_hash: None,
            process_hash_md5: None,
            process_hash_sha1: None,
            parent_chain: vec![ProcessNode {
                pid,
                path: String::new(),
            }],
        }
    }

    async fn enrich_connection_owner_fallback_async(
        attempt: ConnectionAttempt,
    ) -> ConnectionAttempt {
        let fallback = attempt.clone();
        tokio::task::spawn_blocking(move || {
            let mut attempt = attempt;
            Self::enrich_connection_owner(&mut attempt);
            attempt
        })
        .await
        .unwrap_or(fallback)
    }
}

use crate::models::{
    connection_state::ConnectionAttempt,
    process_state::{ProcessInfo, ProcessNode},
};

use super::{dns_service::DnsService, process_service::ProcessService};

#[derive(Clone)]
pub struct ConnectionService {
    process: ProcessService,
    dns: DnsService,
}

pub struct ConnectionContext {
    pub attempt: ConnectionAttempt,
    pub process: ProcessInfo,
    pub dst_host: Option<String>,
}

impl ConnectionService {
    pub fn new(process: ProcessService, dns: DnsService) -> Self {
        Self { process, dns }
    }

    pub async fn resolve(&self, attempt: ConnectionAttempt) -> ConnectionContext {
        let mut attempt =
            crate::utils::pid_resolver::PidResolverState::enrich_connection_owner_async(attempt)
                .await;

        let process = if attempt.pid == 0 {
            ProcessInfo {
                pid: attempt.pid,
                path: "Kernel connection".to_string(),
                args: Vec::new(),
                cwd: None,
                env_preview: Vec::new(),
                env_map: std::collections::HashMap::new(),
                process_hash: None,
                process_hash_md5: None,
                process_hash_sha1: None,
                parent_chain: vec![ProcessNode {
                    pid: attempt.pid,
                    path: "Kernel connection".to_string(),
                }],
            }
        } else {
            match self.process.inspect(attempt.pid).await {
                Ok(info) => info,
                Err(_) => ProcessInfo {
                    pid: attempt.pid,
                    path: String::new(),
                    args: Vec::new(),
                    cwd: None,
                    env_preview: Vec::new(),
                    env_map: std::collections::HashMap::new(),
                    process_hash: None,
                    process_hash_md5: None,
                    process_hash_sha1: None,
                    parent_chain: vec![ProcessNode {
                        pid: attempt.pid,
                        path: String::new(),
                    }],
                },
            }
        };

        let mut dst_host = if attempt.dst_port == 53 {
            attempt.dns_query.take()
        } else {
            None
        };
        if dst_host.is_none() {
            dst_host = self.dns.lookup_ip(attempt.dst_addr).await;
        }

        ConnectionContext {
            attempt,
            process,
            dst_host,
        }
    }
}

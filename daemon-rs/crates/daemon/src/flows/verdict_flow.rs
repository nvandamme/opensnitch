use anyhow::Result;

use crate::{
    adapters::proto_mapper::to_proto_connection,
    bus::Bus,
    client::client::Client,
    models::{event::KernelEvent, verdict::VerdictReply},
    services::{dns_service::DnsService, process_service::ProcessService, rule_service::RuleService},
};
use tracing::warn;

use crate::models::process::{ProcessInfo, ProcessNode};

#[derive(Clone)]
pub struct VerdictFlow {
    bus: Bus,
    client: Client,
    rules: RuleService,
    process: ProcessService,
    dns: DnsService,
}

impl VerdictFlow {
    pub fn new(
        bus: Bus,
        client: Client,
        rules: RuleService,
        process: ProcessService,
        dns: DnsService,
    ) -> Self {
        Self {
            bus,
            client,
            rules,
            process,
            dns,
        }
    }

    pub async fn handle_event(&self, event: KernelEvent) -> Result<()> {
        if let KernelEvent::ConnectAttempt(attempt) = event {
                let proc_info = match self.process.inspect(attempt.pid).await {
                    Ok(info) => info,
                    Err(e) => {
                        warn!(pid = attempt.pid, err = %e, "process already gone; using stub info");
                        ProcessInfo {
                            pid: attempt.pid,
                            path: String::new(),
                            args: Vec::new(),
                            cwd: None,
                            env_preview: Vec::new(),
                            process_hash: None,
                            parent_chain: vec![ProcessNode {
                                pid: attempt.pid,
                                path: String::new(),
                            }],
                        }
                    }
                };
            let dst_host = self.dns.lookup(&attempt.dst_ip).await;

            if let Some(allow) = self
                .rules
                .match_attempt(&attempt, &proc_info, dst_host.as_deref())
                .await?
            {
                let _ = self
                    .bus
                    .verdict_tx
                    .send(VerdictReply {
                        request_id: attempt.request_id,
                        allow,
                    })
                    .await;
                return Ok(());
            }

            let pb_conn = to_proto_connection(&attempt, &proc_info, dst_host);

            let mut client = self.client.clone();
            let rule = client.ask_rule(pb_conn).await?;
            let allow = self.rules.upsert_from_proto(&rule).await?;

            let _ = self
                .bus
                .verdict_tx
                .send(VerdictReply {
                    request_id: attempt.request_id,
                    allow,
                })
                .await;
        }

        Ok(())
    }
}

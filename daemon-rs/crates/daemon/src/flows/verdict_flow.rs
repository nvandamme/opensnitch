use anyhow::Result;
use opensnitch_proto::pb;

use crate::{
    adapters::proto_mapper::to_proto_connection,
    bus::Bus,
    client::client::Client,
    models::{
        connection_state::ConnectionAttempt, kernel_event::KernelEvent, verdict_rpc::VerdictReply,
    },
    services::{
        config_service::ConfigService, dns_service::DnsService, process_service::ProcessService,
        rule_service::RuleService, stats_service::StatsService,
    },
};
use tracing::{debug, warn};

use crate::models::process_state::{ProcessInfo, ProcessNode};

#[derive(Clone)]
pub struct VerdictFlow {
    bus: Bus,
    config: ConfigService,
    rules: RuleService,
    process: ProcessService,
    dns: DnsService,
    stats: StatsService,
}

impl VerdictFlow {
    pub fn new(
        bus: Bus,
        config: ConfigService,
        rules: RuleService,
        process: ProcessService,
        dns: DnsService,
        stats: StatsService,
    ) -> Self {
        Self {
            bus,
            config,
            rules,
            process,
            dns,
            stats,
        }
    }

    pub async fn handle_event(&self, _event: KernelEvent) -> Result<()> {
        Ok(())
    }

    pub async fn fast_allow_daemon_owned(&self, request_id: u64) {
        self.stats.on_daemon_owned_fast_allow();

        let verdict = VerdictReply {
            request_id,
            allow: true,
            reject: false,
        };

        match self.bus.verdict_tx.try_send(verdict) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(verdict)) => {
                let _ = self.bus.verdict_tx.send(verdict).await;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    pub async fn handle_connect_attempt(&self, attempt: ConnectionAttempt) {
        let request_id = attempt.request_id;
        if let Err(err) = self.process_connect_attempt(attempt).await {
            warn!(request_id, err = %err, "verdict flow failed; applying default action");
            self.stats.on_ignored();
            let action = self.config.snapshot().await.default_action;
            let _ = self
                .bus
                .verdict_tx
                .send(VerdictReply {
                    request_id,
                    allow: action.allows(),
                    reject: action.rejects(),
                })
                .await;
        }
    }

    async fn process_connect_attempt(&self, attempt: ConnectionAttempt) -> Result<()> {
        if attempt.pid == std::process::id() {
            debug!(
                pid = attempt.pid,
                "accepting daemon-owned connection attempt"
            );
            self.fast_allow_daemon_owned(attempt.request_id).await;
            return Ok(());
        }

        let attempt = crate::utils::pid_resolver::enrich_connection_owner_async(attempt).await;

        let proc_info = match self.process.inspect(attempt.pid).await {
            Ok(info) => info,
            Err(err) => {
                warn!(pid = attempt.pid, err = %err, "process already gone; using stub info");
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

        let mut dst_host = if attempt.dst_port == 53 {
            attempt.dns_query.clone()
        } else {
            None
        };
        if dst_host.is_none() {
            dst_host = self.dns.lookup(&attempt.dst_ip).await;
        }
        self.stats
            .on_connection_metadata(&proc_info.path, dst_host.as_deref());

        let pb_conn = to_proto_connection(&attempt, &proc_info, dst_host.clone());

        if let Some(allow) = self
            .rules
            .match_attempt(&attempt, &proc_info, dst_host.as_deref())
            .await?
        {
            self.stats.on_rule_hit();
            self.stats
                .on_event(pb_conn.clone(), Some(decision_rule_summary(allow)));
            let _ = self
                .bus
                .verdict_tx
                .send(VerdictReply {
                    request_id: attempt.request_id,
                    allow: allow.allow,
                    reject: allow.reject,
                })
                .await;
            return Ok(());
        }

        self.stats.on_rule_miss();

        let client_addr = self.config.snapshot().await.client_addr;
        let mut client = Client::connect(&client_addr).await?;
        let rule = client.ask_rule(pb_conn.clone()).await?;
        let decision = self.rules.upsert_from_proto(&rule).await?;

        self.stats.on_rule_hit();
        self.stats
            .on_event(pb_conn, Some(decision_rule_summary(decision)));

        let _ = self
            .bus
            .verdict_tx
            .send(VerdictReply {
                request_id: attempt.request_id,
                allow: decision.allow,
                reject: decision.reject,
            })
            .await;

        Ok(())
    }
}

fn decision_rule_summary(decision: crate::services::rule_service::RuleMatchDecision) -> pb::Rule {
    pb::Rule {
        created: 0,
        name: "runtime-match".to_string(),
        description: "matched existing runtime rule".to_string(),
        enabled: true,
        precedence: false,
        nolog: false,
        action: if decision.allow {
            "allow".to_string()
        } else if decision.reject {
            "reject".to_string()
        } else {
            "deny".to_string()
        },
        duration: "always".to_string(),
        operator: None,
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{
        bus::build_bus,
        config::Config,
        flows::verdict_flow::VerdictFlow,
        models::{
            connection_state::{ConnectionAttempt, TransportProtocol},
            firewall_state::{FirewallBackend, FirewallState},
            kernel_event::KernelEvent,
        },
        services::{
            config_service::ConfigService,
            dns_service::DnsService,
            process_service::ProcessService,
            rule_service::{RuleMatchDecision, RuleService},
            stats_service::StatsService,
        },
    };

    use super::decision_rule_summary;

    #[test]
    fn decision_rule_summary_maps_action_names() {
        let allow = decision_rule_summary(RuleMatchDecision {
            allow: true,
            reject: false,
        });
        assert_eq!(allow.action, "allow");

        let reject = decision_rule_summary(RuleMatchDecision {
            allow: false,
            reject: true,
        });
        assert_eq!(reject.action, "reject");
    }

    #[tokio::test]
    async fn handle_event_ignores_non_connection_events() -> Result<()> {
        let (bus, _rx) = build_bus(4);
        let flow = VerdictFlow::new(
            bus,
            ConfigService::new(Config::default()),
            RuleService::default(),
            ProcessService::default(),
            DnsService::default(),
            StatsService::default(),
        );

        flow.handle_event(KernelEvent::FirewallState(FirewallState {
            enabled: false,
            backend: FirewallBackend::Nftables,
        }))
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn daemon_owned_connection_is_fast_allowed() -> Result<()> {
        let (bus, mut rx) = build_bus(4);
        let flow = VerdictFlow::new(
            bus,
            ConfigService::new(Config::default()),
            RuleService::default(),
            ProcessService::default(),
            DnsService::default(),
            StatsService::default(),
        );

        flow.handle_connect_attempt(ConnectionAttempt {
            request_id: 42,
            protocol: TransportProtocol::Tcp,
            src_ip: "127.0.0.1".to_string(),
            src_port: 50000,
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 8080,
            dns_query: None,
            pid: std::process::id(),
            uid: 1000,
        })
        .await;

        let verdict = rx.verdict_rx.recv().await.expect("verdict reply");
        assert_eq!(verdict.request_id, 42);
        assert!(verdict.allow);
        assert!(!verdict.reject);

        Ok(())
    }
}

use std::sync::Arc;

use anyhow::Result;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bus::{build_bus, Bus, BusRx},
    client::client::Client,
    flows::{notification_flow::NotificationFlow, verdict_flow::VerdictFlow},
    runtime::RuntimeHandles,
    services::{
        config_service::ConfigService,
        dns_service::DnsService,
        firewall_service::FirewallService,
        process_service::ProcessService,
        rule_service::RuleService,
    },
    workers,
};

#[derive(Clone)]
pub struct Daemon {
    inner: Arc<DaemonInner>,
}

struct DaemonInner {
    config: ConfigService,
    bus: Bus,
    rules: RuleService,
    process: ProcessService,
    dns: DnsService,
    firewall: FirewallService,
    shutdown: CancellationToken,
}

impl Daemon {
    pub async fn run(client_addr: Option<&str>) -> Result<()> {
        let (daemon, rx) = Self::bootstrap(client_addr).await?;
        daemon.serve(rx).await
    }

    pub async fn bootstrap(client_addr: Option<&str>) -> Result<(Self, BusRx)> {
        let (bus, rx) = build_bus(512);
        let config = crate::config::Config::load_from_default_locations()?
            .with_client_addr_override(client_addr);
        let config_service = ConfigService::new(config.clone());
        let rules = RuleService::default();
        rules.load_path(&config.rules_path).await?;
        let firewall = FirewallService::new(&config)?;
        if let Err(err) = firewall.ensure_rules().await {
            warn!(backend = config.firewall_backend.as_str(), "firewall bootstrap skipped: {err}");
        }

        let daemon = Self {
            inner: Arc::new(DaemonInner {
                config: config_service,
                bus,
                rules,
                process: ProcessService::default(),
                dns: DnsService::default(),
                firewall,
                shutdown: CancellationToken::new(),
            }),
        };

        Ok((daemon, rx))
    }

    pub async fn serve(&self, rx: BusRx) -> Result<()> {
        let config = self.inner.config.snapshot().await;
        let mut client = Client::connect(&config.client_addr).await?;
        self.startup_handshake(&mut client).await?;

        let verdict_flow = VerdictFlow::new(
            self.inner.bus.clone(),
            client.clone(),
            self.inner.rules.clone(),
            self.inner.process.clone(),
            self.inner.dns.clone(),
        );

        let notification_flow = NotificationFlow::new(self.inner.bus.clone(), client);

        let mut handles = RuntimeHandles::new();
        self.spawn_workers(&mut handles);
        self.spawn_tasks(&mut handles, rx, verdict_flow, notification_flow);

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received");
            }
            _ = self.inner.shutdown.cancelled() => {
                info!("shutdown requested");
            }
        }

        self.shutdown().await;
        handles.join_all().await;

        Ok(())
    }

    async fn startup_handshake(&self, client: &mut Client) -> Result<()> {
        let config = self.inner.config.snapshot().await;
        let rules = self.inner.rules.list_proto().await;
        let firewall = self.inner.firewall.snapshot().await;
        let system_firewall = self.inner.firewall.system_firewall().await;
        let subscribe_cfg = client.build_subscribe_config(
            &config,
            rules,
            firewall.enabled,
            system_firewall,
        );
        let subscribe_reply = client.subscribe(subscribe_cfg).await?;

        info!(
            client_name = %subscribe_reply.name,
            client_version = %subscribe_reply.version,
            "subscribed to control client"
        );

        let ping_reply = client
            .ping(opensnitch_proto::pb::PingRequest {
                id: 1,
                stats: None,
            })
            .await?;

        info!(ping_id = ping_reply.id, "ping successful");

        Ok(())
    }

    fn spawn_workers(&self, handles: &mut RuntimeHandles) {
        handles.push_worker(
            "seccomp",
            workers::seccomp_worker::spawn(self.inner.bus.clone(), self.inner.shutdown.clone()),
        );

        handles.push_worker(
            "ebpf",
            workers::ebpf_worker::spawn(self.inner.bus.clone(), self.inner.shutdown.clone()),
        );

        handles.push_worker(
            "netlink-proc",
            workers::netlink_proc_worker::spawn(self.inner.bus.clone(), self.inner.shutdown.clone()),
        );

        handles.push_worker(
            "dns",
            workers::dns_worker::spawn(self.inner.dns.clone(), self.inner.shutdown.clone()),
        );
    }

    fn spawn_tasks(
        &self,
        handles: &mut RuntimeHandles,
        rx: BusRx,
        verdict_flow: VerdictFlow,
        notification_flow: NotificationFlow,
    ) {
        handles.push_task(
            "notifications",
            self.spawn_notification_task(notification_flow),
        );

        handles.push_task(
            "kernel-events",
            self.spawn_kernel_task(verdict_flow, rx.kernel_rx),
        );

        handles.push_task(
            "client-commands",
            self.spawn_client_command_task(rx.client_cmd_rx),
        );

        handles.push_task(
            "verdict-replies",
            self.spawn_verdict_reply_task(rx.verdict_rx),
        );
    }

    fn spawn_notification_task(&self, flow: NotificationFlow) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                res = flow.run() => {
                    if let Err(err) = res {
                        error!("notification flow failed: {err}");
                    }
                }
            }
        })
    }

    fn spawn_kernel_task(
        &self,
        flow: VerdictFlow,
        mut kernel_rx: tokio::sync::mpsc::Receiver<crate::models::event::KernelEvent>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = kernel_rx.recv() => {
                        match msg {
                            Some(event) => {
                                if let Err(err) = flow.handle_event(event).await {
                                    error!("verdict flow failed: {err}");
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    fn spawn_client_command_task(
        &self,
        mut client_cmd_rx: tokio::sync::mpsc::Receiver<crate::models::notification::ClientCommand>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();
        let config = self.inner.config.clone();
        let rules = self.inner.rules.clone();
        let firewall = self.inner.firewall.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = client_cmd_rx.recv() => {
                        match msg {
                            Some(cmd) => {
                                match cmd {
                                    crate::models::notification::ClientCommand::SetInterception(enabled) => {
                                        firewall.set_interception(enabled).await;
                                        tracing::info!(enabled, "updated interception state");
                                    }
                                    crate::models::notification::ClientCommand::SetFirewall(enabled) => {
                                        firewall.set_enabled(enabled).await;
                                        if enabled {
                                            let current = config.snapshot().await;
                                            if let Err(err) = firewall.reload_from_config(&current).await {
                                                tracing::error!("failed to reload firewall config: {err}");
                                            }
                                            if let Err(err) = firewall.ensure_rules().await {
                                                tracing::error!("failed to enable firewall: {err}");
                                            }
                                        }
                                    }
                                    crate::models::notification::ClientCommand::ReloadFirewall => {
                                        let current = config.snapshot().await;
                                        if let Err(err) = firewall.reload_from_config(&current).await {
                                            tracing::error!("failed to reload firewall config: {err}");
                                        }
                                    }
                                    crate::models::notification::ClientCommand::ApplyConfig(raw_json) => {
                                        match config.apply_raw_json(&raw_json).await {
                                            Ok(updated) => {
                                                if let Err(err) = rules.load_path(&updated.rules_path).await {
                                                    tracing::error!("failed to reload rules after config change: {err}");
                                                }
                                                if let Err(err) = firewall.reload_from_config(&updated).await {
                                                    tracing::error!("failed to reload firewall after config change: {err}");
                                                }
                                            }
                                            Err(err) => tracing::error!("failed to apply config update: {err}"),
                                        }
                                    }
                                    crate::models::notification::ClientCommand::UpsertRules(updated_rules) => {
                                        for rule in updated_rules {
                                            if let Err(err) = rules.upsert_from_proto(&rule).await {
                                                tracing::error!(rule = %rule.name, "failed to upsert rule: {err}");
                                            }
                                        }
                                    }
                                    crate::models::notification::ClientCommand::DeleteRules(rule_names) => {
                                        for rule_name in rule_names {
                                            if let Err(err) = rules.delete_by_name(&rule_name).await {
                                                tracing::error!(rule = %rule_name, "failed to delete rule: {err}");
                                            }
                                        }
                                    }
                                    crate::models::notification::ClientCommand::ReloadRules => {
                                        if let Err(err) = rules.reload().await {
                                            tracing::error!("failed to reload rules: {err}");
                                        }
                                    }
                                    crate::models::notification::ClientCommand::Shutdown => {
                                        shutdown.cancel();
                                        break;
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    fn spawn_verdict_reply_task(
        &self,
        mut verdict_rx: tokio::sync::mpsc::Receiver<crate::models::verdict::VerdictReply>,
    ) -> JoinHandle<()> {
        let shutdown = self.inner.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    msg = verdict_rx.recv() => {
                        match msg {
                            Some(reply) => {
                                tracing::info!(
                                    "verdict reply request_id={} allow={}",
                                    reply.request_id,
                                    reply.allow
                                );
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }
}

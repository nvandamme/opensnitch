use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::Result;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{Config, ProcMonitorMethod},
    models::ui_alert::UiAlert,
    services::{firewall::FirewallService, rule::RuleService, stats::StatsService},
    workers::runtime::control::WorkerControl,
};

pub(crate) type ProcWorkerReconfigure = Arc<
    dyn Fn(Option<ProcMonitorMethod>) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct ConfigService {
    snapshot_tx: watch::Sender<Arc<Config>>,
    snapshot_rx: watch::Receiver<Arc<Config>>,
}

impl ConfigService {
    pub(super) fn publish_config_snapshot(&self, config: Config) {
        let _ = self.snapshot_tx.send(Arc::new(config));
    }

    pub fn new(config: Config) -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(config));
        Self {
            snapshot_tx,
            snapshot_rx,
        }
    }

    pub fn get_snapshot(&self) -> Arc<Config> {
        self.snapshot_rx.borrow().clone()
    }

    pub async fn parse_raw_json(&self, raw_json: &str) -> Result<Config> {
        let current = self.get_snapshot();
        Self::parse_raw_json_with_base(current.as_ref(), raw_json)
    }

    pub async fn persist_raw_json(&self, raw_json: &str) -> Result<()> {
        let current = self.get_snapshot();
        Self::persist_raw_json_at(current.config_path.as_path(), raw_json).await
    }

    pub async fn set_snapshot(&self, config: Config) {
        self.publish_config_snapshot(config);
    }

    pub async fn set_log_level(&self, level: u32) {
        let mut updated = Arc::unwrap_or_clone(self.get_snapshot());
        updated.log_level = level;
        self.publish_config_snapshot(updated);
    }

    pub(crate) fn spawn_watch_task(
        &self,
        shutdown: CancellationToken,
        rules: RuleService,
        firewall: FirewallService,
        stats: StatsService,
        alert_tx: tokio::sync::mpsc::Sender<UiAlert>,
        reconfigure_proc_workers: ProcWorkerReconfigure,
    ) -> Box<dyn WorkerControl> {
        super::storage::start_config_watch_task(
            self.clone(),
            shutdown,
            rules,
            firewall,
            stats,
            alert_tx,
            reconfigure_proc_workers,
        )
    }
}

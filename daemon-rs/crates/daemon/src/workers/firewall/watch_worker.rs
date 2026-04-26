use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use crate::{
    services::{config::ConfigService, firewall::FirewallService, rule::RuleService},
    utils::duration_parse::{DurationParseOptions, parse_human_duration},
    workers::{
        runtime::control::WorkerControl,
        runtime::watch::control::{EmptyWatchTargetsBehavior, WatchWorkerControl},
    },
};

pub(crate) fn parse_firewall_monitor_interval(raw: &str) -> std::time::Duration {
    let value = raw.trim();
    if value.is_empty() {
        return std::time::Duration::from_secs(10);
    }

    if value == "0" {
        return std::time::Duration::ZERO;
    }

    parse_human_duration(
        value,
        DurationParseOptions {
            allow_fractional: false,
            min_ms: 0,
            min_s: 0,
            min_m: 0,
            min_h: 0,
        },
    )
    .unwrap_or(std::time::Duration::from_secs(10))
}

struct FirewallWatchControl {
    firewall: FirewallService,
    config: ConfigService,
    rules: RuleService,
}

impl WatchWorkerControl for FirewallWatchControl {
    fn worker_name(&self) -> &'static str {
        "firewall-watch"
    }

    fn poll_interval(&self) -> std::time::Duration {
        let snapshot = self.config.get_snapshot();
        let interval = parse_firewall_monitor_interval(snapshot.firewall_monitor_interval.as_str());
        if interval.is_zero() {
            // Keep a low wake-up cadence when monitor checks are disabled.
            Self::poll_every_secs(1)
        } else {
            interval
        }
    }

    fn targets(&self) -> Vec<PathBuf> {
        Self::path_targets(&self.config.get_snapshot().firewall_config_path)
    }

    fn empty_targets_behavior(&self) -> EmptyWatchTargetsBehavior {
        EmptyWatchTargetsBehavior::WarnPollFallback
    }

    fn scan<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let firewall = self.firewall.clone();
        let config = self.config.clone();
        let rules = self.rules.clone();
        Box::pin(async move {
            let snapshot = config.get_snapshot();
            let interval =
                parse_firewall_monitor_interval(snapshot.firewall_monitor_interval.as_str());
            if interval.is_zero() {
                return;
            }
            match firewall.heal_if_drifted().await {
                Ok(true) => {
                    if let Err(err) = rules.rebuild_caches_from_snapshot().await {
                        tracing::warn!(
                            "failed to rebuild rule caches after firewall drift heal: {err}"
                        );
                    }
                }
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!("failed to heal firewall drift: {err}");
                }
            }
        })
    }
}

pub(crate) fn start(
    firewall: FirewallService,
    config: ConfigService,
    rules: RuleService,
    shutdown: CancellationToken,
) -> Box<dyn WorkerControl> {
    crate::platform::firewall::monitor::spawn_nft_drift_listener(
        firewall.clone(),
        rules.clone(),
        shutdown.clone(),
    );
    FirewallWatchControl {
        firewall,
        config,
        rules,
    }
    .build(shutdown)
}

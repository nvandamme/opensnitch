use tokio_util::sync::CancellationToken;
use transport_wire_core::{
    WireRuleSubscriptionEntry, WireSubscriptionAction, WireSubscriptionReply,
    WireSubscriptionStatistics,
};

use crate::models::subscription::rpc::SubscriptionCommand;
use crate::services::audit::AuditService;
use crate::services::stats::StatsService;

#[derive(Clone, Default)]
pub struct SubscriptionService;

impl SubscriptionService {
    // Kept for API parity with the enabled subscription service.
    #[allow(dead_code)]
    pub fn new<T, U>(_storage: T, _root_dir: U) -> Self {
        Self
    }

    pub fn with_system_defaults() -> Self {
        Self
    }

    // Kept for API parity with the enabled subscription service.
    #[allow(dead_code)]
    pub async fn handle_wire_command(&self, command: SubscriptionCommand) -> WireSubscriptionReply {
        let operation = match command.operation {
            crate::models::subscription::rpc::SubscriptionOperation::Unspecified => {
                WireSubscriptionAction::Unspecified as i32
            }
            crate::models::subscription::rpc::SubscriptionOperation::List => {
                WireSubscriptionAction::List as i32
            }
            crate::models::subscription::rpc::SubscriptionOperation::Apply => {
                WireSubscriptionAction::Apply as i32
            }
            crate::models::subscription::rpc::SubscriptionOperation::Delete => {
                WireSubscriptionAction::Delete as i32
            }
            crate::models::subscription::rpc::SubscriptionOperation::Refresh => {
                WireSubscriptionAction::Refresh as i32
            }
            crate::models::subscription::rpc::SubscriptionOperation::Deploy => {
                WireSubscriptionAction::Deploy as i32
            }
        };

        WireSubscriptionReply {
            operation,
            accepted: false,
            message: "subscription feature is disabled in this build".to_string(),
            ..Default::default()
        }
    }

    // Kept for API parity with the enabled subscription service.
    #[allow(dead_code)]
    pub fn subscription_stats(&self) -> WireSubscriptionStatistics {
        WireSubscriptionStatistics::default()
    }

    pub fn subscription_stats_with_rules(
        &self,
        _list_rule_paths: &[(std::sync::Arc<str>, std::path::PathBuf)],
    ) -> WireSubscriptionStatistics {
        WireSubscriptionStatistics::default()
    }

    // Kept for API parity with the enabled subscription service.
    #[allow(dead_code)]
    pub fn build_rule_subscription_entries(
        &self,
        _list_rule_paths: &[(std::sync::Arc<str>, std::path::PathBuf)],
    ) -> Vec<WireRuleSubscriptionEntry> {
        Vec::new()
    }

    // Kept for API parity with the enabled subscription service.
    #[allow(dead_code)]
    pub fn spawn_scheduler(
        &self,
        shutdown: CancellationToken,
        _stats: StatsService,
        _rules: crate::services::rule::RuleService,
        _audit: AuditService,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            shutdown.cancelled().await;
        })
    }
}

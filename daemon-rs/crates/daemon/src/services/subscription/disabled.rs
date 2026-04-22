use opensnitch_proto::pb;
use tokio_util::sync::CancellationToken;

use crate::services::stats::StatsService;

#[derive(Clone, Default)]
pub struct SubscriptionService;

impl SubscriptionService {
    #[allow(dead_code)]
    pub fn new<T, U>(_storage: T, _root_dir: U) -> Self {
        Self
    }

    pub fn with_system_defaults() -> Self {
        Self
    }

    pub async fn handle_request(&self, req: pb::SubscriptionRequest) -> pb::SubscriptionReply {
        let operation = pb::SubscriptionOperation::try_from(req.operation)
            .unwrap_or(pb::SubscriptionOperation::Unspecified) as i32;

        pb::SubscriptionReply {
            operation,
            accepted: false,
            message: "subscription feature is disabled in this build".to_string(),
            ..Default::default()
        }
    }

    pub fn counts(&self) -> (u64, u64, u64) {
        (0, 0, 0)
    }

    pub fn spawn_scheduler(
        &self,
        shutdown: CancellationToken,
        _stats: StatsService,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            shutdown.cancelled().await;
        })
    }
}

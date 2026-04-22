use opensnitch_proto::pb;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::SubscriptionService;
use super::refresh_timing::scheduler_wake_duration;
use crate::services::stats::StatsService;

impl SubscriptionService {
    fn scheduler_wake_duration(&self) -> std::time::Duration {
        scheduler_wake_duration(
            self.storage
                .list_records()
                .into_iter()
                .filter(|r| r.enabled)
                .map(|r| r.next_refresh_after),
        )
    }

    pub fn spawn_scheduler(
        &self,
        shutdown: CancellationToken,
        stats: StatsService,
    ) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            debug!("subscription scheduler: started");
            loop {
                let sleep_for = service.scheduler_wake_duration();
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(sleep_for) => {}
                }
                if shutdown.is_cancelled() {
                    break;
                }

                let req = pb::SubscriptionRequest {
                    operation: pb::SubscriptionOperation::Refresh as i32,
                    force: false,
                    ..Default::default()
                };
                let reply = service.handle_request(req).await;
                if !(reply.subscriptions.is_empty() && !reply.accepted) {
                    debug!(
                        message = %reply.message,
                        accepted = reply.accepted,
                        "subscription scheduler: refresh cycle"
                    );
                }

                let (total, ready, error) = service.counts();
                stats.update_subscription_counts(total, ready, error);
            }
            debug!("subscription scheduler: stopped");
        })
    }
}

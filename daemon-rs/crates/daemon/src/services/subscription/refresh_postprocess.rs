use super::SubscriptionService;

impl SubscriptionService {
    pub(super) async fn apply_refresh_postprocess(
        &self,
        sync_layout: bool,
        errors: &mut Vec<String>,
    ) {
        if sync_layout && let Err(err) = self.sync_layout().await {
            errors.push(format!("layout sync failed: {err}"));
        }

        self.flush_storage_best_effort().await;
    }
}

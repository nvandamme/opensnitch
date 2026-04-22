use super::audit::AuditService;
use crate::services::lifecycle::ServiceFactory;

impl ServiceFactory for AuditService {
    type FactoryInput = usize;

    async fn init(capacity: Self::FactoryInput) -> anyhow::Result<Self> {
        Ok(Self::new(capacity))
    }
}

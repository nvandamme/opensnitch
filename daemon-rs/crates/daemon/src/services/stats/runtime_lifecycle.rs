use std::env;

use super::stats::StatsService;
use crate::services::lifecycle::{ServiceFactory, ServiceRuntimeControl};

const GO_BACKEND_COMPAT_VERSION: &str = "1.9.0";
static DAEMON_VERSION: std::sync::OnceLock<std::sync::RwLock<String>> = std::sync::OnceLock::new();

impl StatsService {
    fn resolve_daemon_version() -> String {
        env::var("OPENSNITCH_DAEMON_VERSION")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| GO_BACKEND_COMPAT_VERSION.to_string())
    }

    pub(super) fn daemon_version_string() -> String {
        let cache =
            DAEMON_VERSION.get_or_init(|| std::sync::RwLock::new(Self::resolve_daemon_version()));
        cache
            .read()
            .map(|value| value.clone())
            .unwrap_or_else(|_| GO_BACKEND_COMPAT_VERSION.to_string())
    }
    pub(crate) fn reload_daemon_version_from_env() {
        let next = Self::resolve_daemon_version();
        let cache = DAEMON_VERSION.get_or_init(|| std::sync::RwLock::new(next.clone()));
        if let Ok(mut value) = cache.write() {
            *value = next;
        }
    }
}

impl ServiceFactory for StatsService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> anyhow::Result<Self> {
        Ok(Self::default())
    }
}

impl ServiceRuntimeControl for StatsService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> anyhow::Result<()> {
        StatsService::reload_daemon_version_from_env();
        Ok(())
    }
}

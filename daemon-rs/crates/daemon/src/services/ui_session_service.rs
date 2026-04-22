use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::RwLock;

#[derive(Clone)]
pub struct UiSessionService {
    connected: Arc<AtomicBool>,
    connected_default_action: Arc<RwLock<crate::config::DefaultAction>>,
}

impl Default for UiSessionService {
    fn default() -> Self {
        Self {
            connected: Arc::new(AtomicBool::new(false)),
            connected_default_action: Arc::new(RwLock::new(crate::config::DefaultAction::Deny)),
        }
    }
}

impl UiSessionService {
    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub async fn set_connected_default_action(&self, action: crate::config::DefaultAction) {
        *self.connected_default_action.write().await = action;
    }

    pub async fn effective_default_action(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
    ) -> crate::config::DefaultAction {
        if self.is_connected() {
            *self.connected_default_action.read().await
        } else {
            disconnected_default_action
        }
    }

    pub async fn effective_default_duration(
        &self,
        disconnected_default_duration: crate::config::DefaultDuration,
    ) -> crate::config::DefaultDuration {
        disconnected_default_duration
    }
}

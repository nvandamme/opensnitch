use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone)]
pub struct UiSessionService {
    snapshot_tx: watch::Sender<Arc<UiSessionSnapshot>>,
    snapshot_rx: watch::Receiver<Arc<UiSessionSnapshot>>,
}

#[derive(Clone)]
struct UiSessionSnapshot {
    connected: bool,
    connected_default_action: crate::config::DefaultAction,
}

impl Default for UiSessionService {
    fn default() -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(UiSessionSnapshot {
            connected: false,
            connected_default_action: crate::config::DefaultAction::Deny,
        }));
        Self {
            snapshot_tx,
            snapshot_rx,
        }
    }
}

impl UiSessionService {
    fn publish_snapshot(&self, next: UiSessionSnapshot) {
        let _ = self.snapshot_tx.send_replace(Arc::new(next));
    }

    pub fn set_connected(&self, connected: bool) {
        let connected_default_action = self.snapshot_rx.borrow().connected_default_action;
        let next = UiSessionSnapshot {
            connected,
            connected_default_action,
        };
        self.publish_snapshot(next);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_connected(&self) -> bool {
        self.snapshot_rx.borrow().connected
    }

    pub fn set_connected_default_action(&self, action: crate::config::DefaultAction) {
        let connected = self.snapshot_rx.borrow().connected;
        let next = UiSessionSnapshot {
            connected,
            connected_default_action: action,
        };
        self.publish_snapshot(next);
    }

    pub fn effective_default_action(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
    ) -> crate::config::DefaultAction {
        let snapshot = self.snapshot_rx.borrow();
        if snapshot.connected {
            snapshot.connected_default_action
        } else {
            disconnected_default_action
        }
    }

    pub fn effective_default_duration(
        &self,
        disconnected_default_duration: crate::config::DefaultDuration,
    ) -> crate::config::DefaultDuration {
        disconnected_default_duration
    }

    pub fn effective_defaults(
        &self,
        disconnected_default_action: crate::config::DefaultAction,
        disconnected_default_duration: crate::config::DefaultDuration,
    ) -> (crate::config::DefaultAction, crate::config::DefaultDuration) {
        let action = self.effective_default_action(disconnected_default_action);
        let duration = self.effective_default_duration(disconnected_default_duration);
        (action, duration)
    }
}

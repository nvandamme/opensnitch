use std::sync::atomic::Ordering;

use crate::models::process_worker_state::ProcessWorkerState;
use crate::services::lifecycle::{ServiceEvent, ServiceState, ServiceStatus};

use super::process::ProcessRuntime;

impl ProcessRuntime {
    pub(super) fn current_status(&self) -> ServiceStatus {
        ServiceStatus {
            state: self
                .lifecycle_state
                .lock()
                .map(|state| *state)
                .unwrap_or(ServiceState::Degraded),
            last_error: self
                .last_error
                .lock()
                .map(|err| err.clone())
                .unwrap_or_else(|_| Some("process intent state unavailable".to_string())),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_subscribers.load(Ordering::Relaxed);
        let _ = self.event_subscribers.load(Ordering::Relaxed);
        let _ = self.status_tx.send(self.current_status());
    }

    pub(super) fn transition_state(&self, to: ServiceState) {
        let from = self
            .lifecycle_state
            .lock()
            .map(|mut state| {
                let from = *state;
                *state = to;
                from
            })
            .unwrap_or(ServiceState::Degraded);

        self.publish_status();
        let _ = self.event_tx.send(ServiceEvent::StateChanged {
            from,
            to,
            last_error: self.last_error.lock().ok().and_then(|err| err.clone()),
        });
    }

    pub(super) fn set_error(&self, error: Option<String>) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = error;
        }
        self.publish_status();
    }

    pub(super) fn snapshot(&self) -> ProcessWorkerState {
        self.state.lock().map(|state| *state).unwrap_or_default()
    }
}

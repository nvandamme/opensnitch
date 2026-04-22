use std::sync::{Arc, atomic::AtomicUsize};
use std::time::Duration;

use tokio::sync::{broadcast, watch};

use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceFactory, ServiceLifecycle, ServiceMonitorStats,
    ServiceRuntimeControl, ServiceState, ServiceStatus, StatusSubscription,
    monitor_stats_from_counters, subscribe_events_with_counter, subscribe_status_with_counter,
};

use super::{TaskLifecycleEvent, TaskRuntime, TaskService};

#[derive(Clone)]
pub(crate) struct TaskLifecycle {
    status_tx: watch::Sender<ServiceStatus>,
    event_tx: broadcast::Sender<ServiceEvent>,
    status_subscribers: Arc<AtomicUsize>,
    event_subscribers: Arc<AtomicUsize>,
    lifecycle_state: ServiceState,
    last_error: Option<String>,
}

impl Default for TaskLifecycle {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(256);
        Self {
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: ServiceState::Uninitialized,
            last_error: None,
        }
    }
}

impl TaskLifecycle {
    fn status(&self) -> ServiceStatus {
        ServiceStatus {
            state: self.lifecycle_state,
            last_error: self.last_error.clone(),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_tx.send(self.status());
    }

    fn transition_state(&mut self, to: ServiceState) {
        let from = self.lifecycle_state;
        self.lifecycle_state = to;
        self.publish_status();
        let _ = self.event_tx.send(ServiceEvent::StateChanged {
            from,
            to,
            last_error: self.last_error.clone(),
        });
    }

    fn set_error(&mut self, err: Option<String>) {
        self.last_error = err;
        self.publish_status();
    }

    fn clear_error_and_transition(&mut self, to: ServiceState) {
        self.set_error(None);
        self.transition_state(to);
    }
}

impl ServiceLifecycle for TaskRuntime {
    async fn init(&mut self) -> anyhow::Result<()> {
        self.lifecycle
            .clear_error_and_transition(ServiceState::Stopped);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.lifecycle
            .clear_error_and_transition(ServiceState::Running);
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        let paused = self.task_handles.len();
        self.emit_lifecycle_event(TaskLifecycleEvent::PausedAll { task_count: paused })
            .await;
        self.lifecycle
            .clear_error_and_transition(ServiceState::Paused);
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        let resumed = self.task_handles.len();
        self.emit_lifecycle_event(TaskLifecycleEvent::ResumedAll {
            task_count: resumed,
        })
        .await;
        self.lifecycle
            .clear_error_and_transition(ServiceState::Running);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        let task_keys: Vec<String> = self.task_handles.keys().cloned().collect();
        for task_key in task_keys {
            self.emit_lifecycle_event(TaskLifecycleEvent::Removed {
                task_name: task_key.clone(),
                task_key,
            })
            .await;
        }
        let stopped = TaskService::stop_runtime_tasks(&mut self.task_handles);
        tracing::info!(
            stopped,
            "stopped temporary runtime tasks after notification disconnect"
        );
        self.lifecycle
            .clear_error_and_transition(ServiceState::Stopped);
        Ok(())
    }

    async fn reload(&mut self) -> anyhow::Result<()> {
        self.stop().await?;
        self.start().await
    }

    async fn quiesce(&mut self) -> anyhow::Result<()> {
        self.lifecycle
            .clear_error_and_transition(ServiceState::Quiescing);
        Ok(())
    }

    async fn drain(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        loop {
            self.task_handles
                .retain(|_, runtime| !runtime.handle.is_finished());
            if self.task_handles.is_empty() {
                self.lifecycle.set_error(None);
                return Ok(());
            }
            if start.elapsed() >= timeout {
                let err = format!(
                    "task runtime drain timed out with {} running task(s)",
                    self.task_handles.len()
                );
                self.lifecycle.set_error(Some(err.clone()));
                self.lifecycle.transition_state(ServiceState::Degraded);
                let _ = self
                    .lifecycle
                    .event_tx
                    .send(ServiceEvent::HealthCheckFailed { error: err.clone() });
                anyhow::bail!(err);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        if self.lifecycle.lifecycle_state == ServiceState::Degraded {
            let err = self
                .lifecycle
                .last_error
                .clone()
                .unwrap_or_else(|| "service degraded".to_string());
            let _ = self
                .lifecycle
                .event_tx
                .send(ServiceEvent::HealthCheckFailed { error: err.clone() });
            anyhow::bail!(err);
        }
        Ok(())
    }

    fn status(&self) -> ServiceStatus {
        self.lifecycle.status()
    }

    async fn reset(&mut self) -> anyhow::Result<()> {
        self.stop().await?;
        self.lifecycle.set_error(None);
        let _ = self.lifecycle.event_tx.send(ServiceEvent::Message {
            text: "service state reset".to_string(),
        });
        Ok(())
    }

    fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        Ok(subscribe_status_with_counter(
            &self.lifecycle.status_tx,
            &self.lifecycle.status_subscribers,
        ))
    }

    fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        Ok(subscribe_events_with_counter(
            &self.lifecycle.event_tx,
            &self.lifecycle.event_subscribers,
        ))
    }

    fn monitor_stats(&self) -> ServiceMonitorStats {
        monitor_stats_from_counters(
            &self.lifecycle.status_subscribers,
            &self.lifecycle.event_subscribers,
        )
    }
}

impl ServiceFactory for TaskService {
    type FactoryInput = ();

    async fn init(_input: Self::FactoryInput) -> anyhow::Result<Self> {
        Ok(Self)
    }
}

impl ServiceRuntimeControl for TaskService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> anyhow::Result<()> {
        Ok(())
    }
}

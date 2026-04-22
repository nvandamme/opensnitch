use std::time::Duration;

use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceLifecycle, ServiceMonitorStats, ServiceState,
    ServiceStatus, StatusSubscription, clear_error_and_transition_mut,
    monitor_stats_from_counters, subscribe_events_with_counter, subscribe_status_with_counter,
};

use super::{TaskLifecycleEvent, TaskRuntime, TaskRuntimeService};

#[tonic::async_trait]
impl ServiceLifecycle for TaskRuntime {
    async fn init(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition_mut(
            self,
            TaskRuntime::mark_last_error,
            TaskRuntime::transition_state,
            ServiceState::Stopped,
        );
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition_mut(
            self,
            TaskRuntime::mark_last_error,
            TaskRuntime::transition_state,
            ServiceState::Running,
        );
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        let paused = self.task_handles.len();
        self.emit_lifecycle_event(TaskLifecycleEvent::PausedAll { task_count: paused })
            .await;
        clear_error_and_transition_mut(
            self,
            TaskRuntime::mark_last_error,
            TaskRuntime::transition_state,
            ServiceState::Paused,
        );
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        let resumed = self.task_handles.len();
        self.emit_lifecycle_event(TaskLifecycleEvent::ResumedAll {
            task_count: resumed,
        })
        .await;
        clear_error_and_transition_mut(
            self,
            TaskRuntime::mark_last_error,
            TaskRuntime::transition_state,
            ServiceState::Running,
        );
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
        let stopped = TaskRuntimeService::stop_runtime_tasks(&mut self.task_handles);
        tracing::info!(
            stopped,
            "stopped temporary runtime tasks after notification disconnect"
        );
        clear_error_and_transition_mut(
            self,
            TaskRuntime::mark_last_error,
            TaskRuntime::transition_state,
            ServiceState::Stopped,
        );
        Ok(())
    }

    async fn reload(&mut self) -> anyhow::Result<()> {
        self.stop().await?;
        self.start().await
    }

    async fn quiesce(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition_mut(
            self,
            TaskRuntime::mark_last_error,
            TaskRuntime::transition_state,
            ServiceState::Quiescing,
        );
        Ok(())
    }

    async fn drain(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        loop {
            self.task_handles
                .retain(|_, runtime| !runtime.handle.is_finished());
            if self.task_handles.is_empty() {
                self.mark_last_error(None);
                return Ok(());
            }
            if start.elapsed() >= timeout {
                let err = format!(
                    "task runtime drain timed out with {} running task(s)",
                    self.task_handles.len()
                );
                self.mark_last_error(Some(err.clone()));
                self.transition_state(ServiceState::Degraded);
                let _ = self
                    .event_tx
                    .send(ServiceEvent::HealthCheckFailed { error: err.clone() });
                anyhow::bail!(err);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        if self.lifecycle_state == ServiceState::Degraded {
            let err = self
                .last_error
                .clone()
                .unwrap_or_else(|| "service degraded".to_string());
            let _ = self
                .event_tx
                .send(ServiceEvent::HealthCheckFailed { error: err.clone() });
            anyhow::bail!(err);
        }
        Ok(())
    }

    fn status(&self) -> ServiceStatus {
        self.current_status()
    }

    async fn reset(&mut self) -> anyhow::Result<()> {
        self.stop().await?;
        self.mark_last_error(None);
        let _ = self.event_tx.send(ServiceEvent::Message {
            text: "service state reset".to_string(),
        });
        Ok(())
    }

    fn subscribe_status(&self) -> anyhow::Result<StatusSubscription> {
        Ok(subscribe_status_with_counter(
            &self.status_tx,
            &self.status_subscribers,
        ))
    }

    fn subscribe_events(&self) -> anyhow::Result<EventSubscription> {
        Ok(subscribe_events_with_counter(
            &self.event_tx,
            &self.event_subscribers,
        ))
    }

    fn monitor_stats(&self) -> ServiceMonitorStats {
        monitor_stats_from_counters(&self.status_subscribers, &self.event_subscribers)
    }
}

use crate::services::lifecycle::{
    EventSubscription, ServiceLifecycle, ServiceMonitorStats, ServiceState, ServiceStatus,
    StatusSubscription, clear_error_and_transition, monitor_stats_from_counters,
    subscribe_events_with_counter, subscribe_status_with_counter,
};

use super::process::ProcessRuntime;

#[tonic::async_trait]
impl ServiceLifecycle for ProcessRuntime {
    async fn init(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            ProcessRuntime::set_error,
            ProcessRuntime::transition_state,
            ServiceState::Stopped,
        );
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            ProcessRuntime::set_error,
            ProcessRuntime::transition_state,
            ServiceState::Running,
        );
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            ProcessRuntime::set_error,
            ProcessRuntime::transition_state,
            ServiceState::Paused,
        );
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            ProcessRuntime::set_error,
            ProcessRuntime::transition_state,
            ServiceState::Running,
        );
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Ok(mut st) = self.state.lock() {
            st.worker_count = 0;
            st.ebpf_requested = false;
        }
        clear_error_and_transition(
            self,
            ProcessRuntime::set_error,
            ProcessRuntime::transition_state,
            ServiceState::Stopped,
        );
        Ok(())
    }

    fn status(&self) -> ServiceStatus {
        self.current_status()
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

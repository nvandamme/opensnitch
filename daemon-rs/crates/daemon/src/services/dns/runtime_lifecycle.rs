use crate::services::lifecycle::{
    EventSubscription, ServiceLifecycle, ServiceMonitorStats, ServiceState, ServiceStatus,
    StatusSubscription, clear_error_and_transition, monitor_stats_from_counters,
    subscribe_events_with_counter, subscribe_status_with_counter,
};
use crate::models::dns_worker_state::DnsWorkerKind;

use super::dns::DnsRuntime;

#[tonic::async_trait]
impl ServiceLifecycle for DnsRuntime {
    async fn init(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            DnsRuntime::set_error,
            DnsRuntime::transition_state,
            ServiceState::Stopped,
        );
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            DnsRuntime::set_error,
            DnsRuntime::transition_state,
            ServiceState::Running,
        );
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            DnsRuntime::set_error,
            DnsRuntime::transition_state,
            ServiceState::Paused,
        );
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        clear_error_and_transition(
            self,
            DnsRuntime::set_error,
            DnsRuntime::transition_state,
            ServiceState::Running,
        );
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Ok(mut st) = self.state.lock() {
            st.worker_kind = DnsWorkerKind::None;
        }
        clear_error_and_transition(
            self,
            DnsRuntime::set_error,
            DnsRuntime::transition_state,
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

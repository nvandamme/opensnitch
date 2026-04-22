use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::{broadcast, watch};

use crate::models::connection_owner::ConnectionOwnerCacheKey;
use crate::services::lifecycle::{
    EventSubscription, ServiceEvent, ServiceFactory, ServiceLifecycle, ServiceMonitorStats,
    ServiceRuntimeControl, ServiceState, ServiceStatus, StatusSubscription,
    monitor_stats_from_counters, subscribe_events_with_counter, subscribe_status_with_counter,
};
use crate::utils::lru_cache::SyncDualLayerLruMap;

use super::ConnectionService;

const fn default_inode_to_pid_cache_capacity() -> usize {
    if cfg!(test) { 8_192 } else { 262_144 }
}

const fn default_inode_key_to_pid_cache_capacity() -> usize {
    if cfg!(test) { 8_192 } else { 262_144 }
}

const DEFAULT_INODE_TO_PID_CACHE_CAPACITY: usize = default_inode_to_pid_cache_capacity();
const DEFAULT_INODE_KEY_TO_PID_CACHE_CAPACITY: usize = default_inode_key_to_pid_cache_capacity();
pub(super) static INODE_TO_PID_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_INODE_TO_PID_CACHE_CAPACITY);
pub(super) static INODE_KEY_TO_PID_CACHE_CAPACITY: AtomicUsize =
    AtomicUsize::new(DEFAULT_INODE_KEY_TO_PID_CACHE_CAPACITY);
pub(super) static INODE_TO_PID: OnceLock<SyncDualLayerLruMap<u32, u32>> = OnceLock::new();
pub(super) static INODE_KEY_TO_PID: OnceLock<SyncDualLayerLruMap<ConnectionOwnerCacheKey, u32>> =
    OnceLock::new();

#[derive(Clone)]
pub(crate) struct ConnectionLifecycle {
    status_tx: watch::Sender<ServiceStatus>,
    event_tx: broadcast::Sender<ServiceEvent>,
    status_subscribers: Arc<AtomicUsize>,
    event_subscribers: Arc<AtomicUsize>,
    lifecycle_state: Arc<std::sync::Mutex<ServiceState>>,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl Default for ConnectionLifecycle {
    fn default() -> Self {
        let (status_tx, _) = watch::channel(ServiceStatus {
            state: ServiceState::Uninitialized,
            last_error: None,
        });
        let (event_tx, _) = broadcast::channel(64);
        Self {
            status_tx,
            event_tx,
            status_subscribers: Arc::new(AtomicUsize::new(0)),
            event_subscribers: Arc::new(AtomicUsize::new(0)),
            lifecycle_state: Arc::new(std::sync::Mutex::new(ServiceState::Uninitialized)),
            last_error: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl ConnectionLifecycle {
    pub(crate) fn mark_running(&self) {
        self.clear_error_and_transition(ServiceState::Running);
    }

    fn clear_error_and_transition(&self, to: ServiceState) {
        self.set_error(None);
        self.transition_state(to);
    }

    fn current_status(&self) -> ServiceStatus {
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
                .unwrap_or_else(|_| Some("connection lifecycle state unavailable".to_string())),
        }
    }

    fn publish_status(&self) {
        let _ = self.status_tx.send(self.current_status());
    }

    fn transition_state(&self, to: ServiceState) {
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

    fn set_error(&self, error: Option<String>) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = error;
        }
        self.publish_status();
    }
}

impl ConnectionService {
    pub(crate) fn configure_pid_owner_cache_capacities(inode_cap: usize, inode_key_cap: usize) {
        let inode_cap = inode_cap.max(1);
        let inode_key_cap = inode_key_cap.max(1);
        INODE_TO_PID_CACHE_CAPACITY.store(inode_cap, Ordering::Relaxed);
        INODE_KEY_TO_PID_CACHE_CAPACITY.store(inode_key_cap, Ordering::Relaxed);

        if let Some(cache) = INODE_TO_PID.get() {
            cache.set_capacity(inode_cap);
        }
        if let Some(cache) = INODE_KEY_TO_PID.get() {
            cache.set_capacity(inode_key_cap);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn reset_pid_owner_caches() {
        if let Some(cache) = INODE_TO_PID.get() {
            cache.clear();
        }
        if let Some(cache) = INODE_KEY_TO_PID.get() {
            cache.clear();
        }
    }

    pub(super) fn cache() -> &'static SyncDualLayerLruMap<u32, u32> {
        INODE_TO_PID.get_or_init(|| {
            SyncDualLayerLruMap::new(INODE_TO_PID_CACHE_CAPACITY.load(Ordering::Relaxed).max(1))
        })
    }

    pub(super) fn key_cache() -> &'static SyncDualLayerLruMap<ConnectionOwnerCacheKey, u32> {
        INODE_KEY_TO_PID.get_or_init(|| {
            SyncDualLayerLruMap::new(
                INODE_KEY_TO_PID_CACHE_CAPACITY
                    .load(Ordering::Relaxed)
                    .max(1),
            )
        })
    }
}

impl ServiceFactory for ConnectionService {
    type FactoryInput = (
        crate::services::process::ProcessService,
        crate::services::dns::DnsService,
    );

    async fn init(input: Self::FactoryInput) -> anyhow::Result<Self> {
        Ok(Self::new(input.0, input.1))
    }
}

impl ServiceRuntimeControl for ConnectionService {
    type ReloadInput = ();

    async fn reload(&mut self, _input: Self::ReloadInput) -> anyhow::Result<()> {
        Self::reset_pid_owner_caches();
        Ok(())
    }
}

impl ServiceLifecycle for ConnectionLifecycle {
    async fn init(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Stopped);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Running);
        Ok(())
    }

    async fn pause(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Paused);
        Ok(())
    }

    async fn resume(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Running);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.clear_error_and_transition(ServiceState::Stopped);
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

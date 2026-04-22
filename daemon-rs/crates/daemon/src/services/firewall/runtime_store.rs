use std::sync::Arc;

use tokio::sync::watch;

pub(crate) use crate::models::firewall_runtime::FirewallRuntime;

#[derive(Clone)]
pub(crate) struct FirewallRuntimeStore {
    snapshot_tx: watch::Sender<Arc<FirewallRuntime>>,
    snapshot_rx: watch::Receiver<Arc<FirewallRuntime>>,
}

impl FirewallRuntimeStore {
    pub(crate) fn new(initial_runtime: FirewallRuntime) -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(initial_runtime));
        Self {
            snapshot_tx,
            snapshot_rx,
        }
    }

    pub(crate) fn snapshot(&self) -> Arc<FirewallRuntime> {
        self.snapshot_rx.borrow().clone()
    }

    pub(crate) fn publish(&self, next: FirewallRuntime) {
        self.snapshot_tx.send_replace(Arc::new(next));
    }

    pub(crate) fn build_and_publish<F>(&self, build: F) -> Arc<FirewallRuntime>
    where
        F: FnOnce(&FirewallRuntime) -> FirewallRuntime,
    {
        let current = self.snapshot();
        let next = Arc::new(build(current.as_ref()));
        self.snapshot_tx.send_replace(next.clone());
        next
    }
}
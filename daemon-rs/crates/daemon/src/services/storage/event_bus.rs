use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::mpsc::{SyncSender, TrySendError, sync_channel},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::DashMap;

use tokio::sync::broadcast;

use super::storage::{StorageEvent, StorageOperation};

const STORAGE_EVENT_BUS_INGRESS_CAPACITY: usize = 1024;

#[derive(Debug)]
struct StorageIngressEvent {
    domain: &'static str,
    operation: StorageOperation,
    path: PathBuf,
}

#[derive(Clone, Debug)]
pub(super) struct StorageEventBus {
    ingress_tx: SyncSender<StorageIngressEvent>,
    tx: broadcast::Sender<Arc<StorageEvent>>,
    path_tx: Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,
    prefix_tx: Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,
    #[cfg_attr(not(test), allow(dead_code))]
    subscribers: Arc<AtomicUsize>,
    dropped_ingress_events: Arc<AtomicUsize>,
}

impl StorageEventBus {
    fn dispatch_event(
        tx: &broadcast::Sender<Arc<StorageEvent>>,
        path_tx: &Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,
        prefix_tx: &Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,
        domain: &'static str,
        operation: StorageOperation,
        path: &Path,
    ) {
        let event = Arc::new(StorageEvent {
            domain,
            operation,
            path: path.to_path_buf(),
        });
        let _ = tx.send(Arc::clone(&event));

        let path_sender = if let Some(entry) = path_tx.get(path) {
            let sender = entry.clone();
            drop(entry);
            if sender.receiver_count() == 0 {
                path_tx.remove(path);
                return;
            }
            Some(sender)
        } else {
            None
        };

        if let Some(sender) = path_sender {
            let _ = sender.send(Arc::clone(&event));
        }

        let mut prefix_senders = Vec::new();
        let mut stale = Vec::new();
        let mut current = Some(path);

        while let Some(prefix) = current {
            if let Some(entry) = prefix_tx.get(prefix) {
                let sender = entry.clone();
                drop(entry);
                if sender.receiver_count() == 0 {
                    stale.push(prefix.to_path_buf());
                } else {
                    prefix_senders.push(sender);
                }
            }
            current = prefix.parent();
        }

        for key in stale {
            prefix_tx.remove(&key);
        }

        for sender in prefix_senders {
            let _ = sender.send(Arc::clone(&event));
        }
    }

    fn subscribe_scoped(
        &self,
        map: &Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,
        path: &Path,
    ) -> StorageEventSubscription {
        self.subscribers.fetch_add(1, Ordering::Relaxed);
        let sender = map
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(64);
                tx
            })
            .clone();
        StorageEventSubscription::new(sender.subscribe(), self.subscribers.clone())
    }

    pub(super) fn new() -> Self {
        let (ingress_tx, ingress_rx) =
            sync_channel::<StorageIngressEvent>(STORAGE_EVENT_BUS_INGRESS_CAPACITY);
        let (tx, _) = broadcast::channel(256);
        let path_tx = Arc::new(DashMap::new());
        let prefix_tx = Arc::new(DashMap::new());
        let dropped_ingress_events = Arc::new(AtomicUsize::new(0));

        {
            let tx_for_dispatch = tx.clone();
            let path_tx_for_dispatch = Arc::clone(&path_tx);
            let prefix_tx_for_dispatch = Arc::clone(&prefix_tx);
            std::thread::spawn(move || {
                while let Ok(next) = ingress_rx.recv() {
                    Self::dispatch_event(
                        &tx_for_dispatch,
                        &path_tx_for_dispatch,
                        &prefix_tx_for_dispatch,
                        next.domain,
                        next.operation,
                        &next.path,
                    );
                }
            });
        }

        Self {
            ingress_tx,
            tx,
            path_tx,
            prefix_tx,
            subscribers: Arc::new(AtomicUsize::new(0)),
            dropped_ingress_events,
        }
    }

    pub(super) fn subscribe(&self) -> StorageEventSubscription {
        self.subscribers.fetch_add(1, Ordering::Relaxed);
        StorageEventSubscription::new(self.tx.subscribe(), self.subscribers.clone())
    }

    pub(super) fn subscribe_for_path(&self, path: &Path) -> StorageEventSubscription {
        self.subscribe_scoped(&self.path_tx, path)
    }

    pub(super) fn subscribe_for_prefix(&self, path: &Path) -> StorageEventSubscription {
        self.subscribe_scoped(&self.prefix_tx, path)
    }

    pub(super) fn emit(&self, domain: &'static str, operation: StorageOperation, path: &Path) {
        let next = StorageIngressEvent {
            domain,
            operation,
            path: path.to_path_buf(),
        };
        match self.ingress_tx.try_send(next) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped_ingress_events.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped_ingress_events.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn dropped_ingress_events(&self) -> usize {
        self.dropped_ingress_events.load(Ordering::Relaxed)
    }

    pub(super) fn emit_read(&self, domain: &'static str, path: &Path) {
        self.emit(domain, StorageOperation::Read, path);
    }

    pub(super) fn emit_write(&self, domain: &'static str, path: &Path) {
        self.emit(domain, StorageOperation::Write, path);
    }

    pub(super) fn emit_delete(&self, domain: &'static str, path: &Path) {
        self.emit(domain, StorageOperation::Delete, path);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct StorageEventSubscription {
    receiver: broadcast::Receiver<Arc<StorageEvent>>,
    active_counter: Arc<AtomicUsize>,
}

impl StorageEventSubscription {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(
        receiver: broadcast::Receiver<Arc<StorageEvent>>,
        active_counter: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            receiver,
            active_counter,
        }
    }
}

impl Deref for StorageEventSubscription {
    type Target = broadcast::Receiver<Arc<StorageEvent>>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl DerefMut for StorageEventSubscription {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}

impl Drop for StorageEventSubscription {
    fn drop(&mut self) {
        self.active_counter.fetch_sub(1, Ordering::Relaxed);
    }
}

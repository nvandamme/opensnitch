use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::DashMap;

use tokio::sync::broadcast;

use super::storage::{StorageEvent, StorageOperation};

#[derive(Clone, Debug)]
pub(super) struct StorageEventBus {
    tx: broadcast::Sender<Arc<StorageEvent>>,
    path_tx: Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,
    prefix_tx: Arc<DashMap<PathBuf, broadcast::Sender<Arc<StorageEvent>>>>,    #[cfg_attr(not(test), allow(dead_code))]
    subscribers: Arc<AtomicUsize>,
}

impl StorageEventBus {
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
        let (tx, _) = broadcast::channel(256);
        Self {
            tx,
            path_tx: Arc::new(DashMap::new()),
            prefix_tx: Arc::new(DashMap::new()),
            subscribers: Arc::new(AtomicUsize::new(0)),
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
        let event = Arc::new(StorageEvent {
            domain,
            operation,
            path: path.to_path_buf(),
        });
        let _ = self.tx.send(Arc::clone(&event));

        let path_sender = if let Some(entry) = self.path_tx.get(path) {
            let sender = entry.clone();
            drop(entry);
            if sender.receiver_count() == 0 {
                self.path_tx.remove(path);
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
            if let Some(entry) = self.prefix_tx.get(prefix) {
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
            self.prefix_tx.remove(&key);
        }

        for sender in prefix_senders {
            let _ = sender.send(Arc::clone(&event));
        }
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
    fn new(receiver: broadcast::Receiver<Arc<StorageEvent>>, active_counter: Arc<AtomicUsize>) -> Self {
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

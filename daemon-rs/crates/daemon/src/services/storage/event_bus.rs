use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::broadcast;

use super::storage::{StorageEvent, StorageOperation};

#[derive(Clone, Debug)]
pub(super) struct StorageEventBus {
    tx: broadcast::Sender<StorageEvent>,
    path_tx: Arc<Mutex<HashMap<PathBuf, broadcast::Sender<StorageEvent>>>>,
    prefix_tx: Arc<Mutex<HashMap<PathBuf, broadcast::Sender<StorageEvent>>>>,
    #[cfg_attr(not(test), allow(dead_code))]
    subscribers: Arc<AtomicUsize>,
}

impl StorageEventBus {
    fn subscribe_scoped(
        &self,
        map: &Arc<Mutex<HashMap<PathBuf, broadcast::Sender<StorageEvent>>>>,
        path: &Path,
        lock_error: &'static str,
    ) -> StorageEventSubscription {
        self.subscribers.fetch_add(1, Ordering::Relaxed);

        let sender = {
            let mut scoped = map.lock().expect(lock_error);
            scoped
                .entry(path.to_path_buf())
                .or_insert_with(|| {
                    let (tx, _) = broadcast::channel(64);
                    tx
                })
                .clone()
        };

        StorageEventSubscription::new(sender.subscribe(), self.subscribers.clone())
    }

    pub(super) fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            tx,
            path_tx: Arc::new(Mutex::new(HashMap::new())),
            prefix_tx: Arc::new(Mutex::new(HashMap::new())),
            subscribers: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) fn subscribe(&self) -> StorageEventSubscription {
        self.subscribers.fetch_add(1, Ordering::Relaxed);
        StorageEventSubscription::new(self.tx.subscribe(), self.subscribers.clone())
    }

    pub(super) fn subscribe_for_path(&self, path: &Path) -> StorageEventSubscription {
        self.subscribe_scoped(&self.path_tx, path, "storage path subscribers mutex poisoned")
    }

    pub(super) fn subscribe_for_prefix(&self, path: &Path) -> StorageEventSubscription {
        self.subscribe_scoped(
            &self.prefix_tx,
            path,
            "storage prefix subscribers mutex poisoned",
        )
    }

    pub(super) fn emit(&self, domain: &'static str, operation: StorageOperation, path: &Path) {
        let event = StorageEvent {
            domain,
            operation,
            path: path.to_path_buf(),
        };
        let _ = self.tx.send(event.clone());

        let path_sender = {
            let mut path_tx = self
                .path_tx
                .lock()
                .expect("storage path subscribers mutex poisoned");
            let sender = path_tx.get(path).cloned();
            if let Some(ref sender) = sender
                && sender.receiver_count() == 0
            {
                path_tx.remove(path);
                return;
            }
            sender
        };

        if let Some(sender) = path_sender {
            let _ = sender.send(event.clone());
        }

        let prefix_senders = {
            let mut prefix_tx = self
                .prefix_tx
                .lock()
                .expect("storage prefix subscribers mutex poisoned");

            let mut senders = Vec::new();
            let mut stale = Vec::new();
            let mut current = Some(path);

            while let Some(prefix) = current {
                if let Some(sender) = prefix_tx.get(prefix).cloned() {
                    if sender.receiver_count() == 0 {
                        stale.push(prefix.to_path_buf());
                    } else {
                        senders.push(sender);
                    }
                }
                current = prefix.parent();
            }

            for key in stale {
                prefix_tx.remove(&key);
            }

            senders
        };

        for sender in prefix_senders {
            let _ = sender.send(event.clone());
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
    receiver: broadcast::Receiver<StorageEvent>,
    active_counter: Arc<AtomicUsize>,
}

impl StorageEventSubscription {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(receiver: broadcast::Receiver<StorageEvent>, active_counter: Arc<AtomicUsize>) -> Self {
        Self {
            receiver,
            active_counter,
        }
    }
}

impl Deref for StorageEventSubscription {
    type Target = broadcast::Receiver<StorageEvent>;

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

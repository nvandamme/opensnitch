use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::{models::audit::AuditEvent, utils::ring_buffer::RingBuffer};

const DEFAULT_CHANNEL_CAPACITY: usize = 512;
const DEFAULT_INGRESS_CAPACITY: usize = 1024;

/// In-memory bounded ring of recent [`AuditEvent`] records.
///
/// Thread-safe and cheaply cloneable (wraps an `Arc`).  Used by the UI query
/// path and post-incident drain.  New events silently overwrite the oldest
/// entry when the ring is full.
#[allow(dead_code)]
#[derive(Clone)]
pub struct AuditRing {
    inner: Arc<Mutex<RingBuffer<Arc<AuditEvent>>>>,
}

#[allow(dead_code)] // Public ring API is kept for planned UI/query/drain consumers.
impl AuditRing {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RingBuffer::new(capacity))),
        }
    }

    fn push(&self, event: Arc<AuditEvent>) {
        if let Ok(mut ring) = self.inner.lock() {
            ring.push_overwrite(event);
        }
    }

    /// Drain and return all buffered events, clearing the ring.
    pub fn drain_recent(&self) -> Vec<Arc<AuditEvent>> {
        self.inner
            .lock()
            .map(|mut r| r.drain_all())
            .unwrap_or_default()
    }

    /// Return the number of events currently buffered.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|r| r.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Fan-out broadcast channel with an in-memory ring for audit events.
///
/// `AuditService` is cheaply `Clone`-able; every clone shares the same
/// underlying ingress queue, broadcast sender and ring.  `emit` is
/// non-blocking and fail-open: producers enqueue into a bounded ingress queue
/// via `try_send`, and a dedicated dispatcher thread fans out to ring +
/// broadcast.
///
/// # Example
/// ```ignore
/// let audit = AuditService::new(256);
/// audit.emit(AuditEvent {
///     family: AuditEventFamily::HotPath,
///     kind: AuditEventKind::ClientVerdictSignal(ClientVerdictSignal::AskTimeoutFallback { ... }),
/// });
/// let recent = audit.ring().drain_recent();
/// ```
#[derive(Clone)]
pub struct AuditService {
    ingress_tx: SyncSender<AuditEvent>,
    tx: broadcast::Sender<Arc<AuditEvent>>,
    #[allow(dead_code)] // Kept for planned ring-backed audit query/drain access.
    ring: AuditRing,
}

impl AuditService {
    /// Create a new `AuditService` with `ring_capacity` ring slots.
    pub fn new(ring_capacity: usize) -> Self {
        let (ingress_tx, ingress_rx) = sync_channel::<AuditEvent>(DEFAULT_INGRESS_CAPACITY);
        let (tx, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        let ring = AuditRing::new(ring_capacity);

        {
            let tx_for_dispatch = tx.clone();
            let ring_for_dispatch = ring.clone();
            std::thread::spawn(move || {
                while let Ok(event) = ingress_rx.recv() {
                    let arc = Arc::new(event);
                    ring_for_dispatch.push(arc.clone());
                    let _ = tx_for_dispatch.send(arc);
                }
            });
        }

        Self {
            ingress_tx,
            tx,
            ring,
        }
    }

    /// Emit an audit event.
    ///
    /// The event is offered to a bounded ingress queue. A dedicated
    /// dispatcher thread persists it into the in-memory ring and fans out via
    /// broadcast.
    pub fn emit(&self, event: AuditEvent) {
        match self.ingress_tx.try_send(event) {
            Ok(()) => {}
            // Fail-open by design: do not block or await in producer hot paths.
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Subscribe to the broadcast stream of audit events.
    ///
    /// The returned receiver will receive all events emitted *after* this
    /// call.  The caller is responsible for consuming messages promptly;
    /// lagging receivers may experience `RecvError::Lagged` gaps.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<AuditEvent>> {
        self.tx.subscribe()
    }

    /// Access the in-memory ring for UI query or drain.
    #[allow(dead_code)] // Kept for planned ring-backed audit query/drain access.
    pub fn ring(&self) -> &AuditRing {
        &self.ring
    }
}

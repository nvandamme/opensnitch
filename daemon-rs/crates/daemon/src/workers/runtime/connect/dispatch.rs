use tokio_util::sync::CancellationToken;

use crate::models::connection_state::ConnectionAttempt;

pub(crate) async fn dispatch_connect_attempt_to_worker(
    worker_txs: &[tokio::sync::mpsc::Sender<ConnectionAttempt>],
    next_worker: &mut usize,
    shutdown: &CancellationToken,
    attempt: ConnectionAttempt,
) -> bool {
    if worker_txs.is_empty() {
        return false;
    }

    let worker_count = worker_txs.len();
    if worker_count == 1 {
        let tx = &worker_txs[0];
        return match tx.try_send(attempt) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => {
                tokio::select! {
                    _ = shutdown.cancelled() => false,
                    result = tx.send(attempt) => result.is_ok(),
                }
            }
        };
    }

    let start_idx = if *next_worker < worker_count {
        *next_worker
    } else {
        *next_worker % worker_count
    };
    let mut pending = attempt;
    let mut fallback_idx = None;
    let mut idx = start_idx;

    // Fast path: probe all workers with try_send first to avoid waiting on one full lane.
    for _ in 0..worker_count {
        let tx = &worker_txs[idx];
        match tx.try_send(pending) {
            Ok(()) => {
                *next_worker = if idx + 1 == worker_count { 0 } else { idx + 1 };
                return true;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => {
                pending = attempt;
                if fallback_idx.is_none() {
                    fallback_idx = Some(idx);
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(attempt)) => {
                pending = attempt;
            }
        }
        idx += 1;
        if idx == worker_count {
            idx = 0;
        }
    }

    // Fallback: block on the first observed non-closed lane after probes fail.
    let Some(blocking_idx) = fallback_idx else {
        return false;
    };

    let tx = &worker_txs[blocking_idx];
    tokio::select! {
        _ = shutdown.cancelled() => false,
        result = tx.send(pending) => {
            if result.is_ok() {
                *next_worker = if blocking_idx + 1 == worker_count {
                    0
                } else {
                    blocking_idx + 1
                };
                true
            } else {
                false
            }
        },
    }
}

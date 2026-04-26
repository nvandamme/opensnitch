use std::collections::HashMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use super::state::{
    DECISION_SHARD_COUNT, Decision, DecisionShard, NfqueueRuntimeState, PACKET_SIGNATURE_BYTES,
    PRIMARY_DECISION_TIMEOUT, REPEAT_DECISION_TIMEOUT, REQUEUE_ALIAS_TTL, RUNTIME, RequeueAlias,
};

pub(crate) struct NfqueueDecisionState;

impl NfqueueDecisionState {
    pub(super) fn decision_shard(runtime: &NfqueueRuntimeState, request_id: u64) -> &DecisionShard {
        &runtime.decision_shards[(request_id as usize) & (DECISION_SHARD_COUNT - 1)]
    }

    pub(crate) fn store_decision_if_pending(
        decisions: &mut HashMap<u64, Option<Decision>>,
        request_id: u64,
        decision: Decision,
    ) -> bool {
        let Some(slot) = decisions.get_mut(&request_id) else {
            return false;
        };
        *slot = Some(decision);
        true
    }

    pub(crate) fn wait_for_decision(
        request_id: u64,
        timeout: Duration,
        keep_pending_on_timeout: bool,
    ) -> Option<Decision> {
        let runtime = RUNTIME.get()?;
        let shard = Self::decision_shard(runtime, request_id);
        let mut guard = shard.decisions.lock().ok()?;
        guard.entry(request_id).or_insert(None);

        let deadline = Instant::now() + timeout;
        loop {
            if let Some(Some(value)) = guard.get(&request_id) {
                let out = *value;
                guard.remove(&request_id);
                return Some(out);
            }

            let now = Instant::now();
            if now >= deadline {
                if !keep_pending_on_timeout {
                    guard.remove(&request_id);
                }
                debug!(
                    request_id,
                    "nfqueue verdict timeout, applying configured default action"
                );
                return None;
            }

            let remain = deadline.saturating_duration_since(now);
            let (g, _) = shard.cv.wait_timeout(guard, remain).ok()?;
            guard = g;
        }
    }

    pub(crate) fn decision_timeout_for_queue(
        queue_num: u16,
        repeat_queue_num: Option<u16>,
    ) -> Duration {
        if Some(queue_num) == repeat_queue_num {
            REPEAT_DECISION_TIMEOUT
        } else {
            PRIMARY_DECISION_TIMEOUT
        }
    }

    pub(crate) fn should_keep_pending_on_timeout(
        queue_num: u16,
        repeat_queue_num: Option<u16>,
    ) -> bool {
        repeat_queue_num.is_some() && Some(queue_num) != repeat_queue_num
    }

    pub(crate) fn packet_signature(payload: &[u8], uid: u32, mark: u32) -> u64 {
        let mut hash = 0xcbf29ce484222325_u64;
        for b in uid.to_le_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in mark.to_le_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in (payload.len() as u64).to_le_bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for b in payload.iter().take(PACKET_SIGNATURE_BYTES) {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    pub(crate) fn prune_requeue_aliases(aliases: &DashMap<u64, RequeueAlias>) {
        let now = Instant::now();
        aliases.retain(|_, alias| alias.expires_at > now);
    }

    pub(super) fn resolve_request_id(
        queue_num: u16,
        packet_id: u32,
        payload_signature: u64,
        repeat_queue_num: Option<u16>,
    ) -> u64 {
        if Some(queue_num) == repeat_queue_num
            && let Some(request_id) = Self::claim_requeue_alias(payload_signature)
        {
            return request_id;
        }

        ((queue_num as u64) << 32) | packet_id as u64
    }

    pub(super) fn remember_requeue_alias(payload_signature: u64, request_id: u64) {
        let Some(runtime) = RUNTIME.get() else {
            return;
        };
        // Prune expired entries on the write path only (cold path: only requeued packets hit this).
        // The claim path (called on every repeat-queue packet) is intentionally O(1) — no scan.
        Self::prune_requeue_aliases(&runtime.requeue_aliases);
        runtime.requeue_aliases.insert(
            payload_signature,
            RequeueAlias {
                request_id,
                expires_at: Instant::now() + REQUEUE_ALIAS_TTL,
            },
        );
    }

    fn claim_requeue_alias(payload_signature: u64) -> Option<u64> {
        let runtime = RUNTIME.get()?;
        // Atomic remove + TTL check — O(1), no map scan.
        runtime
            .requeue_aliases
            .remove(&payload_signature)
            .filter(|(_, alias)| alias.expires_at > Instant::now())
            .map(|(_, alias)| alias.request_id)
    }
}

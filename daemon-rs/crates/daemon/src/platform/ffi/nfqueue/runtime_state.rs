use std::collections::HashMap;
use std::sync::atomic::AtomicU8;
use std::sync::{Condvar, Mutex};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use anyhow::Result;

use crate::bus::Bus;
use crate::{config::DefaultAction, tunables::NfqueueOverloadPolicy};

use super::{
    CapabilitySupport, DECISION_SHARD_COUNT, Decision, DecisionShard, NfqueueDecisionState,
    NfqueueRuntimeState, QueueRuntime, RUNTIME, RuntimeState,
};

impl NfqueueRuntimeState {
    fn encode_default_action(action: DefaultAction) -> u8 {
        match action {
            DefaultAction::Allow => 0,
            DefaultAction::Deny => 1,
            DefaultAction::Reject => 2,
        }
    }

    fn decode_default_action(value: u8) -> DefaultAction {
        match value {
            1 => DefaultAction::Deny,
            2 => DefaultAction::Reject,
            _ => DefaultAction::Allow,
        }
    }

    pub(super) fn current_default_action() -> DefaultAction {
        let Some(runtime) = RUNTIME.get() else {
            return DefaultAction::Allow;
        };

        Self::decode_default_action(
            runtime
                .default_action
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    fn encode_overload_policy(policy: NfqueueOverloadPolicy) -> u8 {
        match policy {
            NfqueueOverloadPolicy::FailOpen => 0,
            NfqueueOverloadPolicy::DropFast => 1,
        }
    }

    fn decode_overload_policy(value: u8) -> NfqueueOverloadPolicy {
        match value {
            1 => NfqueueOverloadPolicy::DropFast,
            _ => NfqueueOverloadPolicy::FailOpen,
        }
    }

    pub(super) fn current_overload_policy() -> NfqueueOverloadPolicy {
        let Some(runtime) = RUNTIME.get() else {
            return NfqueueOverloadPolicy::FailOpen;
        };

        Self::decode_overload_policy(
            runtime
                .overload_policy
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub(crate) fn overload_policy() -> NfqueueOverloadPolicy {
        Self::current_overload_policy()
    }

    pub(crate) fn init(
        bus: Bus,
        primary_queue_num: u16,
        default_action: DefaultAction,
        overload_policy: NfqueueOverloadPolicy,
    ) {
        let _ = RUNTIME.set(RuntimeState {
            bus,
            repeat_queue_num: primary_queue_num.saturating_add(1),
            default_action: AtomicU8::new(Self::encode_default_action(default_action)),
            overload_policy: AtomicU8::new(Self::encode_overload_policy(overload_policy)),
            uid_support: AtomicU8::new(CapabilitySupport::Unknown as u8),
            gid_support: AtomicU8::new(CapabilitySupport::Unknown as u8),
            decision_shards: (0..DECISION_SHARD_COUNT)
                .map(|_| DecisionShard {
                    decisions: Mutex::new(HashMap::new()),
                    cv: Condvar::new(),
                })
                .collect(),
            requeue_aliases: DashMap::new(),
        });
    }

    pub(crate) fn set_default_action(action: DefaultAction) {
        let Some(runtime) = RUNTIME.get() else {
            return;
        };

        runtime.default_action.store(
            Self::encode_default_action(action),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub(crate) fn submit_verdict(request_id: u64, allow: bool, reject: bool) {
        let Some(runtime) = RUNTIME.get() else {
            return;
        };
        let shard = NfqueueDecisionState::decision_shard(runtime, request_id);

        let mut guard = shard
            .decisions
            .lock()
            .expect("nfqueue decision mutex poisoned");
        if !NfqueueDecisionState::store_decision_if_pending(
            &mut guard,
            request_id,
            Decision { allow, reject },
        ) {
            debug!(
                request_id,
                "ignoring late verdict reply for non-pending request"
            );
            return;
        }
        shard.cv.notify_all();
    }

    pub(crate) fn run(queue_num: u16, shutdown: CancellationToken) -> Result<()> {
        debug!(queue_num, backend = "ffi", "starting nfqueue backend");
        let q = QueueRuntime::open(queue_num)?;
        q.run(shutdown)
    }
}

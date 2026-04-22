//! Port facade for nfqueue runtime state operations used by flows/workers.

use crate::platform::ffi::nfqueue::NfqueueRuntimeState;
use crate::tunables::NfqueueOverloadPolicy;
use crate::{bus::Bus, config::DefaultAction};

pub(crate) struct NfqueueRuntimePort;

impl NfqueueRuntimePort {
    pub(crate) fn init(
        bus: Bus,
        primary_queue_num: u16,
        default_action: DefaultAction,
        overload_policy: NfqueueOverloadPolicy,
    ) {
        NfqueueRuntimeState::init(bus, primary_queue_num, default_action, overload_policy)
    }

    pub(crate) fn overload_policy() -> NfqueueOverloadPolicy {
        NfqueueRuntimeState::overload_policy()
    }

    pub(crate) fn submit_verdict(request_id: u64, allow: bool, reject: bool) {
        NfqueueRuntimeState::submit_verdict(request_id, allow, reject)
    }
}

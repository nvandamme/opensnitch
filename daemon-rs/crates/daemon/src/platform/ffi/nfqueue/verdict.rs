use tracing::warn;

use crate::{
    config::DefaultAction,
    models::{dns_payload::DnsPayload, kernel_event::KernelEvent},
    platform::adapters::socket_diag::SocketDiagAdapter,
    tunables::NfqueueOverloadPolicy,
};

use super::{
    NF_ACCEPT, NF_DROP, NF_QUEUE, NfqueueDecisionState, NfqueuePacketParser, NfqueueRuntimeState,
    NfqueueVerdictEngine, PacketVerdict, RUNTIME, RejectSocketSpec,
};
use crate::bus::Bus;
use crate::models::connection_state::ConnectionAttempt;

impl NfqueueVerdictEngine {
    pub(crate) fn timeout_fallback_verdict(
        queue_num: u16,
        repeat_queue_num: Option<u16>,
        overload_policy: NfqueueOverloadPolicy,
        default_action: DefaultAction,
        mark: u32,
        reject_spec: Option<&RejectSocketSpec>,
    ) -> PacketVerdict {
        if matches!(overload_policy, NfqueueOverloadPolicy::DropFast) {
            warn!(
                queue_num,
                fallback_reason = "timeout",
                fallback_mode = "drop-fast",
                "nfqueue overload fallback final verdict"
            );
            return PacketVerdict::Drop;
        }

        if let Some(repeat_queue_num) = repeat_queue_num
            && queue_num != repeat_queue_num
        {
            warn!(
                queue_num,
                repeat_queue_num,
                fallback_reason = "timeout",
                fallback_mode = "requeue",
                "nfqueue overload fallback requeue"
            );
            return PacketVerdict::Requeue {
                queue_num: repeat_queue_num,
                mark,
            };
        }

        let verdict =
            Self::default_action_verdict_for_reject_spec(default_action, mark, reject_spec);

        let verdict_name = match verdict {
            PacketVerdict::Accept { .. } => "accept",
            PacketVerdict::AcceptWithPacket { .. } => "accept-with-packet",
            PacketVerdict::Drop => "drop",
            PacketVerdict::Requeue { .. } => "requeue",
        };

        warn!(
            queue_num,
            fallback_reason = "timeout",
            fallback_mode = "default-action",
            default_action = ?default_action,
            verdict = verdict_name,
            "nfqueue overload fallback final verdict"
        );

        verdict
    }

    pub(crate) fn packet_verdict_to_c(verdict: &PacketVerdict) -> (u32, u32) {
        match verdict {
            PacketVerdict::Accept { mark } => (NF_ACCEPT, *mark),
            PacketVerdict::AcceptWithPacket { mark, .. } => (NF_ACCEPT, *mark),
            PacketVerdict::Drop => (NF_DROP, 0),
            PacketVerdict::Requeue { queue_num, mark } => {
                (NF_QUEUE | ((*queue_num as u32) << 16), *mark)
            }
        }
    }

    pub(crate) fn packet_verdict_payload(verdict: &PacketVerdict) -> Option<&[u8]> {
        match verdict {
            PacketVerdict::AcceptWithPacket { packet, .. } if !packet.is_empty() => Some(packet),
            _ => None,
        }
    }

    pub(crate) fn compute_packet_verdict(
        queue_num: u16,
        packet_id: u32,
        payload: &[u8],
        uid: u32,
        mark: u32,
        iface_in_idx: u32,
        iface_out_idx: u32,
    ) -> PacketVerdict {
        let runtime = RUNTIME.get();
        let default_action = NfqueueRuntimeState::current_default_action();
        let overload_policy = NfqueueRuntimeState::current_overload_policy();
        let dns_answers = NfqueuePacketParser::parse_dns_answer_mappings(payload);
        let is_dns_response = !dns_answers.is_empty();

        if let Some(runtime) = runtime {
            for (addr, host) in dns_answers {
                let _ = runtime
                    .bus
                    .kernel_tx
                    .try_send(KernelEvent::DnsUpdate(DnsPayload::answer(host, addr)));
            }
        }

        if is_dns_response {
            return PacketVerdict::Accept { mark };
        }

        let repeat_queue_num = runtime.map(|state| state.repeat_queue_num);
        let mut payload_signature = None;
        let signature_for_request = if Some(queue_num) == repeat_queue_num {
            let signature = NfqueueDecisionState::packet_signature(payload, uid, mark);
            payload_signature = Some(signature);
            signature
        } else {
            0
        };
        let request_id = NfqueueDecisionState::resolve_request_id(
            queue_num,
            packet_id,
            signature_for_request,
            repeat_queue_num,
        );

        if let Some(mut attempt) = NfqueuePacketParser::parse_connection_attempt(
            request_id,
            payload,
            uid,
            iface_in_idx,
            iface_out_idx,
        ) {
            if attempt.dst_port == 53 {
                attempt.dns_query = NfqueuePacketParser::parse_dns_last_question(payload);
            }
            let reject_spec = NfqueuePacketParser::build_reject_socket_spec(&attempt);

            if let Some(runtime) = runtime
                && let Err(_attempt) =
                    Self::enqueue_connect_attempt_non_blocking(&runtime.bus, attempt)
            {
                tracing::debug!(
                    request_id,
                    queue_num,
                    "kernel event queue saturated, applying timeout fallback verdict"
                );
                return Self::timeout_fallback_verdict(
                    queue_num,
                    repeat_queue_num,
                    overload_policy,
                    default_action,
                    mark,
                    reject_spec.as_ref(),
                );
            }

            let decision_timeout =
                NfqueueDecisionState::decision_timeout_for_queue(queue_num, repeat_queue_num);
            let keep_pending_on_timeout =
                NfqueueDecisionState::should_keep_pending_on_timeout(queue_num, repeat_queue_num);

            let decision = match NfqueueDecisionState::wait_for_decision(
                request_id,
                decision_timeout,
                keep_pending_on_timeout,
            ) {
                Some(decision) => decision,
                None => {
                    if keep_pending_on_timeout {
                        let signature = payload_signature.get_or_insert_with(|| {
                            NfqueueDecisionState::packet_signature(payload, uid, mark)
                        });
                        NfqueueDecisionState::remember_requeue_alias(*signature, request_id);
                    }

                    return Self::timeout_fallback_verdict(
                        queue_num,
                        repeat_queue_num,
                        overload_policy,
                        default_action,
                        mark,
                        reject_spec.as_ref(),
                    );
                }
            };

            if !decision.allow
                && decision.reject
                && let Some(spec) = reject_spec.as_ref()
            {
                Self::reject_socket_for_spec(spec);
            }

            return if decision.allow {
                PacketVerdict::Accept { mark }
            } else {
                PacketVerdict::Drop
            };
        }

        Self::default_action_verdict(default_action, mark)
    }

    pub(crate) fn enqueue_connect_attempt_non_blocking(
        bus: &Bus,
        attempt: ConnectionAttempt,
    ) -> std::result::Result<(), ConnectionAttempt> {
        match bus.connect_tx.try_send(attempt) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(attempt)) => Err(attempt),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(attempt)) => Err(attempt),
        }
    }

    fn default_action_verdict(action: DefaultAction, mark: u32) -> PacketVerdict {
        Self::default_action_verdict_for_reject_spec(action, mark, None)
    }

    fn default_action_verdict_for_reject_spec(
        action: DefaultAction,
        mark: u32,
        reject_spec: Option<&RejectSocketSpec>,
    ) -> PacketVerdict {
        if action.allows() {
            PacketVerdict::Accept { mark }
        } else {
            if action.rejects()
                && let Some(spec) = reject_spec
            {
                Self::reject_socket_for_spec(spec);
            }
            PacketVerdict::Drop
        }
    }

    fn reject_socket_for_spec(spec: &RejectSocketSpec) {
        if let Ok(Some(sock)) = SocketDiagAdapter::find_socket(
            spec.family,
            spec.ipproto,
            spec.src,
            spec.src_port,
            spec.dst,
            spec.dst_port,
        ) {
            let _ = SocketDiagAdapter::kill_socket(spec.family, spec.ipproto, &sock);
        }
    }
}

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::{
    bus::{BusCaps, BusState},
    config::DefaultAction,
    models::connection_state::{ConnectionAttempt, TransportProtocol},
    models::dns_payload::DnsPayload,
    models::kernel_event::KernelEvent,
};

use crate::platform::ffi::nfqueue::{
    Decision, NF_ACCEPT, NF_DROP, NF_QUEUE, NfqueueDecisionState, NfqueueMetricsState,
    NfqueueRuntimeState, NfqueueVerdictEngine, PRIMARY_DECISION_TIMEOUT, PacketVerdict,
    QueueMetricsSnapshot, REPEAT_DECISION_TIMEOUT, RUNTIME, RequeueAlias,
};
use crate::tunables::NfqueueOverloadPolicy;

fn reset_queue_metrics() {
    if let Ok(mut metrics_map) = NfqueueMetricsState::queue_metrics_map().lock() {
        metrics_map.clear();
    }
}

fn queue_metrics_test_guard() -> MutexGuard<'static, ()> {
    static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("queue metrics test mutex poisoned")
}

fn queue_metrics_snapshot(queue_num: u16) -> QueueMetricsSnapshot {
    NfqueueMetricsState::queue_metrics_map()
        .lock()
        .ok()
        .and_then(|metrics_map| {
            metrics_map
                .get(&queue_num)
                .copied()
                .map(|m| NfqueueMetricsState::to_snapshot(queue_num, m))
        })
        .unwrap_or_else(|| QueueMetricsSnapshot {
            queue_num,
            ..QueueMetricsSnapshot::default()
        })
}

#[test]
fn timeout_policy_uses_short_primary_and_long_repeat_budget() {
    assert_eq!(
        NfqueueDecisionState::decision_timeout_for_queue(10, Some(11)),
        PRIMARY_DECISION_TIMEOUT
    );
    assert_eq!(
        NfqueueDecisionState::decision_timeout_for_queue(11, Some(11)),
        REPEAT_DECISION_TIMEOUT
    );
    assert!(NfqueueDecisionState::should_keep_pending_on_timeout(
        10,
        Some(11)
    ));
    assert!(!NfqueueDecisionState::should_keep_pending_on_timeout(
        11,
        Some(11)
    ));
}

#[test]
fn store_decision_updates_only_existing_pending_entries() {
    let mut decisions = HashMap::new();
    decisions.insert(7_u64, None);

    assert!(NfqueueDecisionState::store_decision_if_pending(
        &mut decisions,
        7,
        Decision {
            allow: true,
            reject: false,
        }
    ));
    assert!(matches!(
        decisions.get(&7),
        Some(Some(Decision {
            allow: true,
            reject: false
        }))
    ));

    assert!(!NfqueueDecisionState::store_decision_if_pending(
        &mut decisions,
        8,
        Decision {
            allow: false,
            reject: true,
        }
    ));
    assert!(!decisions.contains_key(&8));
}

#[test]
fn packet_signature_is_stable_for_same_metadata() {
    let payload = [0xde_u8, 0xad, 0xbe, 0xef];
    let a = NfqueueDecisionState::packet_signature(&payload, 1000, 42);
    let b = NfqueueDecisionState::packet_signature(&payload, 1000, 42);
    let c = NfqueueDecisionState::packet_signature(&payload, 1001, 42);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn prune_requeue_aliases_removes_expired_entries() {
    let aliases = DashMap::new();
    aliases.insert(
        1,
        RequeueAlias {
            request_id: 10,
            expires_at: Instant::now() - Duration::from_millis(1),
        },
    );
    aliases.insert(
        2,
        RequeueAlias {
            request_id: 11,
            expires_at: Instant::now() + Duration::from_secs(1),
        },
    );

    NfqueueDecisionState::prune_requeue_aliases(&aliases);
    assert!(!aliases.contains_key(&1));
    assert_eq!(aliases.get(&2).map(|v| v.request_id), Some(11));
}

#[test]
fn enqueue_connect_attempt_non_blocking_uses_dedicated_connect_queue() {
    let (bus, mut rx) = BusState::build_with_caps(BusCaps::uniform(1));
    let _ = bus
        .kernel_tx
        .try_send(KernelEvent::DnsUpdate(DnsPayload::answer(
            "localhost",
            "127.0.0.1".parse().expect("test ip should parse"),
        )));

    let attempt = ConnectionAttempt {
        request_id: 1,
        protocol: TransportProtocol::Tcp,
        src_addr: "127.0.0.1".parse().expect("valid ip"),
        src_port: 12345,
        dst_addr: "127.0.0.1".parse().expect("valid ip"),
        dst_port: 80,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: 1000,
        uid: 1000,
    };

    assert!(NfqueueVerdictEngine::enqueue_connect_attempt_non_blocking(&bus, attempt).is_ok());

    let _ = rx.connect_rx.try_recv();
    let _ = rx.kernel_rx.try_recv();
}

#[test]
fn enqueue_connect_attempt_non_blocking_returns_err_when_connect_queue_is_full() {
    let (bus, mut rx) = BusState::build_with_caps(BusCaps::uniform(1));

    let attempt = ConnectionAttempt {
        request_id: 1,
        protocol: TransportProtocol::Tcp,
        src_addr: "127.0.0.1".parse().expect("valid ip"),
        src_port: 12345,
        dst_addr: "127.0.0.1".parse().expect("valid ip"),
        dst_port: 80,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: 1000,
        uid: 1000,
    };

    assert!(
        NfqueueVerdictEngine::enqueue_connect_attempt_non_blocking(&bus, attempt.clone()).is_ok()
    );
    assert!(NfqueueVerdictEngine::enqueue_connect_attempt_non_blocking(&bus, attempt).is_err());

    let _ = rx.connect_rx.try_recv();
}

fn runtime_test_guard() -> MutexGuard<'static, ()> {
    static RUNTIME_TEST_GUARD: Mutex<()> = Mutex::new(());
    RUNTIME_TEST_GUARD
        .lock()
        .expect("runtime test mutex poisoned")
}

fn build_ipv4_dns_response_payload() -> Vec<u8> {
    let mut dns = vec![
        0x12, 0x34, 0x81, 0x80, // id + flags(response)
        0x00, 0x01, // qdcount
        0x00, 0x01, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
    ];

    // Question: example.com A IN
    dns.extend_from_slice(&[
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, // qtype A
        0x00, 0x01, // qclass IN
    ]);

    // Answer: name pointer to question, A record 93.184.216.34
    dns.extend_from_slice(&[
        0xC0, 0x0C, // pointer to question name
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
        0x00, 0x00, 0x00, 0x3C, // TTL 60s
        0x00, 0x04, // rdlength
        93, 184, 216, 34,
    ]);

    let udp_len = (8 + dns.len()) as u16;
    let ip_total_len = (20 + udp_len as usize) as u16;

    let mut payload = vec![0_u8; 20 + 8];
    payload[0] = 0x45; // IPv4, header len 20
    payload[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    payload[8] = 64; // ttl
    payload[9] = 17; // udp
    payload[12..16].copy_from_slice(&[8, 8, 8, 8]);
    payload[16..20].copy_from_slice(&[192, 0, 2, 10]);

    let udp_offset = 20;
    payload[udp_offset..udp_offset + 2].copy_from_slice(&53_u16.to_be_bytes());
    payload[udp_offset + 2..udp_offset + 4].copy_from_slice(&53000_u16.to_be_bytes());
    payload[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    payload[udp_offset + 6..udp_offset + 8].copy_from_slice(&0_u16.to_be_bytes());

    payload.extend_from_slice(&dns);
    payload
}

#[test]
fn dns_response_packet_fast_paths_to_accept_even_when_default_action_is_deny() {
    let _guard = runtime_test_guard();

    if RUNTIME.get().is_none() {
        let (bus, _rx) = BusState::build_with_caps(BusCaps::uniform(16));
        NfqueueRuntimeState::init(
            bus,
            6000,
            DefaultAction::Deny,
            NfqueueOverloadPolicy::FailOpen,
        );
    }
    NfqueueRuntimeState::set_default_action(DefaultAction::Deny);

    let payload = build_ipv4_dns_response_payload();
    let verdict =
        NfqueueVerdictEngine::compute_packet_verdict(6000, 123, &payload, 1000, 0x5a, 0, 0);

    assert!(matches!(verdict, PacketVerdict::Accept { mark: 0x5a }));

    NfqueueRuntimeState::set_default_action(DefaultAction::Allow);
}

fn simulate_timeout_flow(
    primary_queue_num: u16,
    repeat_queue_num: u16,
    overload_policy: NfqueueOverloadPolicy,
    default_action: DefaultAction,
    mark: u32,
) -> (PacketVerdict, PacketVerdict) {
    let first = NfqueueVerdictEngine::timeout_fallback_verdict(
        primary_queue_num,
        Some(repeat_queue_num),
        overload_policy,
        default_action,
        mark,
        None,
    );

    let second = match first {
        PacketVerdict::Requeue { queue_num, mark } => {
            NfqueueVerdictEngine::timeout_fallback_verdict(
                queue_num,
                Some(repeat_queue_num),
                overload_policy,
                default_action,
                mark,
                None,
            )
        }
        _ => first.clone(),
    };

    (first, second)
}

#[test]
fn timeout_requeues_on_primary_queue_and_preserves_mark() {
    let verdict = NfqueueVerdictEngine::timeout_fallback_verdict(
        10,
        Some(11),
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Allow,
        0x2a,
        None,
    );
    match verdict {
        PacketVerdict::Requeue { queue_num, mark } => {
            assert_eq!(queue_num, 11);
            assert_eq!(mark, 0x2a);
        }
        _ => panic!("expected requeue verdict"),
    }
}

#[test]
fn timeout_applies_default_action_on_repeat_queue() {
    let allow_verdict = NfqueueVerdictEngine::timeout_fallback_verdict(
        11,
        Some(11),
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Allow,
        0x99,
        None,
    );
    assert!(matches!(
        allow_verdict,
        PacketVerdict::Accept { mark: 0x99 }
    ));

    let deny_verdict = NfqueueVerdictEngine::timeout_fallback_verdict(
        11,
        Some(11),
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Deny,
        0x99,
        None,
    );
    assert!(matches!(deny_verdict, PacketVerdict::Drop));

    let reject_verdict = NfqueueVerdictEngine::timeout_fallback_verdict(
        11,
        Some(11),
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Reject,
        0x99,
        None,
    );
    assert!(matches!(reject_verdict, PacketVerdict::Drop));
}

#[test]
fn timeout_still_requeues_on_primary_queue() {
    let verdict = NfqueueVerdictEngine::timeout_fallback_verdict(
        10,
        Some(11),
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Deny,
        0x44,
        None,
    );
    assert!(matches!(
        verdict,
        PacketVerdict::Requeue {
            queue_num: 11,
            mark: 0x44
        }
    ));
}

#[test]
fn drop_fast_policy_drops_without_requeue() {
    let (first, second) = simulate_timeout_flow(
        10,
        11,
        NfqueueOverloadPolicy::DropFast,
        DefaultAction::Allow,
        0x33,
    );

    assert!(matches!(first, PacketVerdict::Drop));
    assert!(matches!(second, PacketVerdict::Drop));
}

#[test]
fn c_verdict_encoding_matches_expected_values() {
    assert_eq!(
        NfqueueVerdictEngine::packet_verdict_to_c(&PacketVerdict::Accept { mark: 7 }),
        (NF_ACCEPT, 7)
    );
    assert_eq!(
        NfqueueVerdictEngine::packet_verdict_to_c(&PacketVerdict::Drop),
        (NF_DROP, 0)
    );
    assert_eq!(
        NfqueueVerdictEngine::packet_verdict_to_c(&PacketVerdict::Requeue {
            queue_num: 6,
            mark: 77,
        }),
        (NF_QUEUE | ((6_u32) << 16), 77)
    );
}

#[test]
fn verdict_with_packet_exposes_payload_for_nfq_set_verdict2() {
    let verdict = PacketVerdict::AcceptWithPacket {
        mark: 7,
        packet: vec![1, 2, 3],
    };

    assert_eq!(
        NfqueueVerdictEngine::packet_verdict_to_c(&verdict),
        (NF_ACCEPT, 7)
    );
    assert_eq!(
        NfqueueVerdictEngine::packet_verdict_payload(&verdict),
        Some(&[1, 2, 3][..])
    );
}

#[test]
fn timeout_flow_requeue_then_allow_on_repeat_queue() {
    let (first, second) = simulate_timeout_flow(
        20,
        21,
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Allow,
        0x42,
    );

    assert!(matches!(
        first,
        PacketVerdict::Requeue {
            queue_num: 21,
            mark: 0x42
        }
    ));
    assert!(matches!(second, PacketVerdict::Accept { mark: 0x42 }));
}

#[test]
fn timeout_flow_requeue_then_drop_on_repeat_queue() {
    let (first, second) = simulate_timeout_flow(
        30,
        31,
        NfqueueOverloadPolicy::FailOpen,
        DefaultAction::Deny,
        0xbeef,
    );

    assert!(matches!(
        first,
        PacketVerdict::Requeue {
            queue_num: 31,
            mark: 0xbeef
        }
    ));
    assert!(matches!(second, PacketVerdict::Drop));
}

#[test]
fn queue_metrics_account_packet_verdicts_and_recv_errors() {
    let _guard = queue_metrics_test_guard();
    reset_queue_metrics();

    NfqueueMetricsState::record_packet_verdict(7, &PacketVerdict::Accept { mark: 1 });
    NfqueueMetricsState::record_packet_verdict(7, &PacketVerdict::Drop);
    NfqueueMetricsState::record_packet_verdict(
        7,
        &PacketVerdict::Requeue {
            queue_num: 8,
            mark: 2,
        },
    );
    NfqueueMetricsState::record_recv_error(7);
    NfqueueMetricsState::record_recv_error(7);

    let metrics = queue_metrics_snapshot(7);
    assert_eq!(metrics.packets_total, 3);
    assert_eq!(metrics.verdict_accept, 1);
    assert_eq!(metrics.verdict_drop, 1);
    assert_eq!(metrics.verdict_requeue, 1);
    assert_eq!(metrics.recv_errors, 2);
}

#[test]
fn debug_metrics_snapshot_reports_sorted_queues() {
    let _guard = queue_metrics_test_guard();
    reset_queue_metrics();

    NfqueueMetricsState::record_packet_verdict(9, &PacketVerdict::Accept { mark: 10 });
    NfqueueMetricsState::record_packet_verdict(8, &PacketVerdict::Drop);
    NfqueueMetricsState::record_recv_error(8);

    let snapshot = NfqueueMetricsState::debug_metrics_snapshot();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].queue_num, 8);
    assert_eq!(snapshot[1].queue_num, 9);
    assert_eq!(snapshot[0].packets_total, 1);
    assert_eq!(snapshot[0].verdict_drop, 1);
    assert_eq!(snapshot[0].recv_errors, 1);
    assert_eq!(snapshot[1].packets_total, 1);
    assert_eq!(snapshot[1].verdict_accept, 1);
}

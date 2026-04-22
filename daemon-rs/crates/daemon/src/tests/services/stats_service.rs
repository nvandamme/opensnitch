use crate::config::StatsConfig;
use crate::services::stats_service::StatsService;
use opensnitch_proto::pb;

#[test]
fn bump_limited_counter_evicts_lowest_entry_at_capacity() {
    let mut map =
        std::collections::HashMap::from([("alpha".to_string(), 3), ("beta".to_string(), 1)]);

    StatsService::probe_bump_limited_counter(&mut map, "gamma".to_string(), 2);

    assert_eq!(map.len(), 2);
    assert!(map.contains_key("alpha"));
    assert!(map.contains_key("gamma"));
    assert!(!map.contains_key("beta"));
}

#[test]
fn apply_config_trims_existing_event_backlog() {
    let stats = StatsService::default();
    for index in 0..3 {
        stats.on_event(
            pb::Connection {
                protocol: "tcp".to_string(),
                dst_ip: format!("10.0.0.{index}"),
                ..Default::default()
            },
            None,
        );
    }

    stats.apply_config(StatsConfig {
        max_events: 2,
        max_stats: 5,
        workers: 1,
    });

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.events.len(), 2);
}

#[test]
fn dns_and_ignored_traffic_increment_accepted() {
    let stats = StatsService::default();

    stats.on_dns_resolved();
    stats.on_ignored();

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.dns_responses, 1);
    assert_eq!(snapshot.ignored, 1);
    assert_eq!(snapshot.accepted, 2);
}

#[test]
fn fast_allow_and_fast_deny_counters_are_tracked_separately() {
    let stats = StatsService::default();

    stats.on_fast_allow();
    stats.on_fast_allow();
    stats.on_fast_deny();

    assert_eq!(stats.fast_allow_count(), 2);
    assert_eq!(stats.fast_deny_count(), 1);
    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.connections, 0);
    assert_eq!(snapshot.accepted, 0);
}

#[test]
fn snapshot_if_pending_returns_none_without_events_and_drains_when_present() {
    let stats = StatsService::default();
    assert!(stats.snapshot_if_pending(0).is_none());

    stats.on_event(pb::Connection::default(), None);
    let snapshot = stats.snapshot_if_pending(0).expect("pending snapshot");
    assert_eq!(snapshot.events.len(), 1);
    assert!(stats.snapshot_if_pending(0).is_none());
}

#[test]
fn apply_config_zero_values_keep_existing_limits() {
    let stats = StatsService::default();

    stats.apply_config(StatsConfig {
        max_events: 2,
        max_stats: 3,
        workers: 4,
    });
    stats.apply_config(StatsConfig {
        max_events: 0,
        max_stats: 0,
        workers: 0,
    });

    for index in 0..4 {
        stats.on_event(
            pb::Connection {
                protocol: "tcp".to_string(),
                dst_ip: format!("10.0.1.{index}"),
                ..Default::default()
            },
            None,
        );
    }

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.events.len(), 2);
}

#[test]
fn default_stats_start_time_sets_non_zero_uptime_without_traffic() {
    std::thread::sleep(std::time::Duration::from_secs(1));
    let stats = StatsService::default();
    std::thread::sleep(std::time::Duration::from_secs(1));

    let snapshot = stats.snapshot(0);
    assert!(snapshot.uptime >= 1);
}

#[test]
fn empty_executable_is_counted_like_go_backend() {
    let stats = StatsService::default();

    stats.on_connection_metadata("", None);

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.by_executable.get(""), Some(&1));
}

#[test]
fn go_parity_hit_and_allow_verdict_accounting() {
    let stats = StatsService::default();

    stats.on_rule_hit();
    stats.on_verdict(true);

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.rule_hits, 1);
    assert_eq!(snapshot.rule_misses, 0);
    assert_eq!(snapshot.accepted, 1);
    assert_eq!(snapshot.dropped, 0);
}

#[test]
fn go_parity_missed_default_action_counts_drop() {
    let stats = StatsService::default();

    // Go behavior: miss accounting increments rule_misses+dropped directly,
    // even when runtime default action may later allow traffic.
    stats.on_missed_default_action();

    let snapshot = stats.snapshot(0);
    assert_eq!(snapshot.rule_hits, 0);
    assert_eq!(snapshot.rule_misses, 1);
    assert_eq!(snapshot.accepted, 0);
    assert_eq!(snapshot.dropped, 1);
}

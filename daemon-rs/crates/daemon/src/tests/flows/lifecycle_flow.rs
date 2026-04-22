use std::collections::BTreeSet;

use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    flows::lifecycle::ServiceLifecycleFlow,
    services::{
        connection::ConnectionService, dns::DnsService, firewall::FirewallService,
        process::ProcessService,
    },
    workers::runtime::control::RuntimeHandles,
};

#[tokio::test]
async fn lifecycle_flow_spawns_expected_observers_and_stops_on_shutdown() {
    let shutdown = CancellationToken::new();
    let mut handles = RuntimeHandles::new();

    let config = Config::default();
    let process = ProcessService::default();
    let dns = DnsService::default();
    let firewall = FirewallService::new(&config).expect("build firewall service");
    let connections = ConnectionService::new(process.clone(), dns.clone());

    ServiceLifecycleFlow::new(shutdown.clone()).spawn_observers(
        &mut handles,
        &connections,
        &process,
        &dns,
        &firewall,
    );

    assert_eq!(handles.tasks.len(), 8);

    let names: BTreeSet<&'static str> = handles.tasks.iter().map(|task| task.name).collect();
    let expected: BTreeSet<&'static str> = [
        "connection-status",
        "connection-events",
        "process-status",
        "process-events",
        "dns-status",
        "dns-events",
        "firewall-status",
        "firewall-events",
    ]
    .into_iter()
    .collect();

    assert_eq!(names, expected);

    shutdown.cancel();
    timeout(Duration::from_secs(1), handles.join_all())
        .await
        .expect("lifecycle observer tasks did not stop in time");
}

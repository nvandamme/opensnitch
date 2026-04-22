use crate::services::{
    client::ClientService,
    config::ConfigService,
    connection::ConnectionService,
    dns::DnsService,
    ebpf::EbpfService,
    firewall::FirewallService,
    lifecycle::{ServiceFactory, ServiceRuntimeControl},
    process::ProcessService,
    rule::RuleService,
    stats::StatsService,
    storage::StorageService,
    subscription::SubscriptionService,
    task::TaskService,
};

fn assert_service_contract<T>()
where
    T: ServiceFactory + ServiceRuntimeControl,
{
}

#[test]
fn services_implement_factory_and_runtime_reload_contracts() {
    assert_service_contract::<ClientService>();
    assert_service_contract::<ConfigService>();
    assert_service_contract::<ConnectionService>();
    assert_service_contract::<DnsService>();
    assert_service_contract::<EbpfService>();
    assert_service_contract::<FirewallService>();
    assert_service_contract::<ProcessService>();
    assert_service_contract::<RuleService>();
    assert_service_contract::<StatsService>();
    assert_service_contract::<StorageService>();
    assert_service_contract::<SubscriptionService>();
    assert_service_contract::<TaskService>();
}

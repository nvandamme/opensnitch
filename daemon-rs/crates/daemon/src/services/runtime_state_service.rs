#[allow(dead_code)]
pub trait StatefulService {
    fn service_name(&self) -> &'static str;
}

impl StatefulService for super::config_service::ConfigService {
    fn service_name(&self) -> &'static str {
        "config"
    }
}

impl StatefulService for super::dns_service::DnsService {
    fn service_name(&self) -> &'static str {
        "dns"
    }
}

impl StatefulService for super::ebpf_runtime_service::EbpfRuntimeService {
    fn service_name(&self) -> &'static str {
        "ebpf-runtime"
    }
}

impl StatefulService for super::firewall_service::FirewallService {
    fn service_name(&self) -> &'static str {
        "firewall"
    }
}

impl StatefulService for super::process_service::ProcessService {
    fn service_name(&self) -> &'static str {
        "process"
    }
}

impl StatefulService for super::rule_service::RuleService {
    fn service_name(&self) -> &'static str {
        "rule"
    }
}

impl StatefulService for super::stats_service::StatsService {
    fn service_name(&self) -> &'static str {
        "stats"
    }
}

impl StatefulService for super::watch_service::WatchService {
    fn service_name(&self) -> &'static str {
        "watch"
    }
}

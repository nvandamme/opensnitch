#[cfg(test)]
mod probe_bootstrap {
    #[ctor::ctor]
    fn init_logger_for_tests_module() {
        crate::tests::support::init_test_logging();
    }
}

pub(crate) mod support;

#[path = "services/client.rs"]
mod client;
#[path = "runtime_tasks/command_control.rs"]
mod command_control;
#[path = "parsing/config_parsing.rs"]
mod config_parsing;
#[path = "watch_reload/config_service.rs"]
mod config_service;
#[path = "smoke/daemon_runtime.rs"]
mod daemon_runtime;
#[path = "workers/dns_service.rs"]
mod dns_service;
#[path = "workers/ebpf_runtime_service.rs"]
mod ebpf_runtime_service;
#[path = "firewall/firewall_iptables.rs"]
mod firewall_iptables;
#[path = "firewall/firewall_nft.rs"]
mod firewall_nft;
#[path = "firewall/firewall_privileged.rs"]
mod firewall_privileged;
#[path = "firewall/firewall_service.rs"]
mod firewall_service;
#[path = "firewall/gates.rs"]
mod gates;
#[path = "workers/netlink_addr_worker.rs"]
mod netlink_addr_worker;
#[path = "firewall/nfqueue.rs"]
mod nfqueue;
#[path = "flows/notification_flow.rs"]
mod notification_flow;
#[path = "parsing/pid_resolver.rs"]
mod pid_resolver;
#[path = "parsing/proc_connector.rs"]
mod proc_connector;
#[path = "services/process_service.rs"]
mod process_service;
#[path = "smoke/readonly_smoke.rs"]
mod readonly_smoke;
#[path = "rules/rule_command.rs"]
mod rule_command;
#[path = "rules/rule_record.rs"]
mod rule_record;
#[path = "rules/rule_service.rs"]
mod rule_service;
#[path = "rules/rule_service_match_engine.rs"]
mod rule_service_match_engine;
#[path = "rules/rule_storage.rs"]
mod rule_storage;
#[path = "parsing/socket_diag.rs"]
mod socket_diag;
#[path = "services/stats_service.rs"]
mod stats_service;
#[path = "runtime_tasks/task_runtime.rs"]
mod task_runtime;
#[path = "services/ui_session_service.rs"]
mod ui_session_service;
#[path = "flows/verdict_flow.rs"]
mod verdict_flow;
#[path = "watch_reload/watch_service.rs"]
mod watch_service;
#[path = "workers/workers_dispatch.rs"]
mod workers_dispatch;
#[path = "workers/workers_dns.rs"]
mod workers_dns;
#[path = "workers/workers_ebpf.rs"]
mod workers_ebpf;

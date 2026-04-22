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
#[path = "flows/command_flow.rs"]
mod command_flow;
#[path = "parsing/config_parsing.rs"]
mod config_parsing;
#[path = "parsing/data_contract_ownership.rs"]
mod data_contract_ownership;
#[path = "watch_reload/config_service.rs"]
mod config_service;
#[path = "flows/connect_flow.rs"]
mod connect_flow;
#[path = "smoke/daemon_runtime.rs"]
mod daemon_runtime;
#[path = "workers/dns_service.rs"]
mod dns_service;
#[path = "workers/ebpf_service.rs"]
mod ebpf_service;
#[path = "parsing/hex_parse.rs"]
mod hex_parse;
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
#[path = "flows/kernel_flow.rs"]
mod kernel_flow;
#[path = "flows/lifecycle_flow.rs"]
mod lifecycle_flow;
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
#[path = "parsing/proc_fs.rs"]
mod proc_fs;
#[path = "services/process_service.rs"]
mod process_service;
#[path = "smoke/readonly_smoke.rs"]
mod readonly_smoke;
#[path = "rules/rule_benchmark_support.rs"]
mod rule_benchmark_support;
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
#[path = "parsing/sort_key.rs"]
mod sort_key;
#[path = "parsing/string_iter.rs"]
mod string_iter;
#[path = "flows/stats_flow.rs"]
mod stats_flow;
#[path = "services/stats_service.rs"]
mod stats_service;
#[path = "services/storage_service.rs"]
mod storage_service;
#[path = "services/subscription_service.rs"]
mod subscription_service;
#[path = "services/subscription_refresh_targets.rs"]
mod subscription_refresh_targets;
#[path = "services/subscription_storage.rs"]
mod subscription_storage;
#[path = "runtime_tasks/task_runtime.rs"]
mod task_runtime;
#[path = "services/ui_session_service.rs"]
mod ui_session_service;
#[path = "flows/verdict_flow.rs"]
mod verdict_flow;
#[path = "watch_reload/watch_workers.rs"]
mod watch_workers;
#[path = "workers/workers_dispatch.rs"]
mod workers_dispatch;
#[path = "workers/workers_dns.rs"]
mod workers_dns;
#[path = "workers/workers_ebpf.rs"]
mod workers_ebpf;
#[path = "parsing/atomic_write.rs"]
mod atomic_write;
#[path = "parsing/lru_cache.rs"]
mod lru_cache;
#[path = "parsing/transient_files.rs"]
mod transient_files;

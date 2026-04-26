#[cfg(test)]
mod probe_bootstrap {
    #[ctor::ctor]
    fn init_logger_for_tests_module() {
        crate::tests::support::init_test_logging();
    }
}

pub(crate) mod support;

#[path = "parsing/atomic_write.rs"]
mod atomic_write;
#[path = "services/audit.rs"]
mod audit;
#[path = "parsing/audit_netlink.rs"]
mod audit_netlink;
#[path = "smoke/aya_conn_trace.rs"]
mod aya_conn_trace;
#[path = "smoke/aya_dns_trace.rs"]
mod aya_dns_trace;
#[path = "smoke/aya_proc_trace.rs"]
mod aya_proc_trace;
#[path = "smoke/aya_tunnel_trace.rs"]
mod aya_tunnel_trace;
#[path = "services/client.rs"]
mod client;
#[path = "services/client_session_service.rs"]
mod client_session_service;
#[path = "runtime_tasks/command_control.rs"]
mod command_control;
#[path = "flows/command_flow.rs"]
mod command_flow;
#[path = "parsing/config_parsing.rs"]
mod config_parsing;
#[path = "watch_reload/config_service.rs"]
mod config_service;
#[path = "flows/connect_flow.rs"]
mod connect_flow;
#[path = "smoke/daemon_runtime.rs"]
mod daemon_runtime;
#[path = "parsing/data_contract_ownership.rs"]
mod data_contract_ownership;
#[path = "parsing/dns_ebpf.rs"]
mod dns_ebpf;
#[path = "workers/dns_service.rs"]
mod dns_service;
#[path = "services/ebpf_paths.rs"]
mod ebpf_paths;
#[path = "parsing/ebpf_ringbuf.rs"]
mod ebpf_ringbuf;
#[path = "services/ebpf_runtime_mode.rs"]
mod ebpf_runtime_mode;
#[path = "workers/ebpf_service.rs"]
mod ebpf_service;
#[path = "firewall/firewall_backend_fixtures.rs"]
mod firewall_backend_fixtures;
#[path = "firewall/firewall_iptables.rs"]
mod firewall_iptables;
#[path = "parsing/firewall_monitor.rs"]
mod firewall_monitor;
#[path = "firewall/firewall_netlink.rs"]
mod firewall_netlink;
#[path = "firewall/firewall_nftables.rs"]
mod firewall_nftables;
#[path = "firewall/firewall_privileged.rs"]
mod firewall_privileged;
#[path = "firewall/firewall_service.rs"]
mod firewall_service;
#[path = "firewall/gates.rs"]
mod gates;
#[path = "parsing/hex_parse.rs"]
mod hex_parse;
#[path = "flows/kernel_flow.rs"]
mod kernel_flow;
#[path = "flows/lifecycle_flow.rs"]
mod lifecycle_flow;
#[path = "parsing/lru_cache.rs"]
mod lru_cache;
#[path = "workers/netlink_addr_worker.rs"]
mod netlink_addr_worker;
#[path = "parsing/netlink_control.rs"]
mod netlink_control;
#[path = "parsing/netlink_io.rs"]
mod netlink_io;
#[path = "smoke/netlink_sync_async_harness.rs"]
mod netlink_sync_async_harness;
#[path = "firewall/nfqueue.rs"]
mod nfqueue;
#[path = "nfqueue/nfqueue_netlink.rs"]
mod nfqueue_netlink_adapter;
#[path = "flows/notification_flow.rs"]
mod notification_flow;
#[path = "firewall/openwrt_uci_firewall_adapter.rs"]
#[cfg(feature = "openwrt")]
mod openwrt_uci_firewall_adapter;
#[path = "parsing/pid_resolver.rs"]
mod pid_resolver;
#[path = "parsing/proc_connector.rs"]
mod proc_connector;
#[path = "parsing/proc_ebpf.rs"]
mod proc_ebpf;
#[path = "parsing/proc_fs.rs"]
mod proc_fs;
#[path = "services/process_service.rs"]
mod process_service;
#[path = "smoke/readonly_smoke.rs"]
mod readonly_smoke;
#[path = "parsing/ring_buffer.rs"]
mod ring_buffer;
#[path = "rules/rule_benchmark_support.rs"]
mod rule_benchmark_support;
#[path = "rules/rule_command.rs"]
mod rule_command;
#[path = "rules/rule_migration.rs"]
mod rule_migration;
#[path = "rules/rule_record.rs"]
mod rule_record;
#[path = "rules/rule_service.rs"]
mod rule_service;
#[path = "rules/rule_service_match_engine.rs"]
mod rule_service_match_engine;
#[path = "rules/rule_storage.rs"]
mod rule_storage;
#[path = "parsing/runtime_lifecycle_split.rs"]
mod runtime_lifecycle_split;
#[path = "services/service_lifecycle_contracts.rs"]
mod service_lifecycle_contracts;
#[path = "parsing/socket_diag.rs"]
mod socket_diag;
#[path = "parsing/socket_diag_backend_matrix.rs"]
mod socket_diag_backend_matrix;
#[path = "parsing/sort_key.rs"]
mod sort_key;
#[path = "flows/stats_flow.rs"]
mod stats_flow;
#[path = "services/stats_service.rs"]
mod stats_service;
#[path = "services/storage_service.rs"]
mod storage_service;
#[path = "parsing/string_iter.rs"]
mod string_iter;
#[path = "services/subscription_refresh_targets.rs"]
#[cfg(feature = "subscriptions")]
mod subscription_refresh_targets;
#[path = "services/subscription_service.rs"]
#[cfg(feature = "subscriptions")]
mod subscription_service;
#[path = "services/subscription_storage.rs"]
#[cfg(feature = "subscriptions")]
mod subscription_storage;
#[path = "runtime_tasks/task_runtime.rs"]
mod task_runtime;
#[path = "parsing/transient_files.rs"]
mod transient_files;
#[path = "flows/verdict_flow.rs"]
#[cfg(feature = "transport-wire-grpc-client")]
mod verdict_flow;
#[path = "watch_reload/watch_workers.rs"]
mod watch_workers;
#[path = "workers/workers_dispatch.rs"]
mod workers_dispatch;
#[path = "workers/workers_dns.rs"]
mod workers_dns;
#[path = "workers/workers_ebpf.rs"]
mod workers_ebpf;

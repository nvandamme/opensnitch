#[cfg(test)]
mod test_bootstrap {
    #[ctor::ctor]
    fn init_logger_for_tests_module() {
        crate::utils::test_support::init_test_logging();
    }
}

mod client;
mod command_control;
mod config_parsing;
mod config_service;
mod dns_service;
mod ebpf_runtime_service;
mod firewall_nft;
mod firewall_privileged;
mod firewall_service;
mod gates;
mod notification_flow;
mod pid_resolver;
mod proc_connector;
mod process_service;
mod readonly_smoke;
mod rule_command;
mod rule_service;
mod socket_diag;
mod stats_service;
mod task_runtime;
mod ui_session_service;
mod verdict_flow;
mod watch_service;
mod workers_dispatch;
mod workers_dns;
mod workers_ebpf;

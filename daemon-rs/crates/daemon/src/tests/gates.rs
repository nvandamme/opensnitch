use nix::libc;

use crate::utils::command_path::command_exists;

pub(super) fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub(super) fn opt_in_enabled() -> bool {
    std::env::var("OPENSNITCH_RUN_KERNEL_IT")
        .map(|value| value == "1")
        .unwrap_or(false)
}

pub(super) fn strict_mode() -> bool {
    std::env::var("OPENSNITCH_KERNEL_IT_STRICT")
        .map(|value| value == "1")
        .unwrap_or(false)
}

pub(super) fn strict_mode_requires_iptables() -> bool {
    std::env::var("OPENSNITCH_KERNEL_IT_REQUIRE_IPTABLES")
        .map(|value| value == "1")
        .unwrap_or(false)
}

pub(super) fn skip_if_not_opted_in() -> bool {
    !opt_in_enabled()
}

pub(super) fn skip_if_not_root() -> bool {
    !is_root()
}

#[test]
fn kernel_harness_preflight() {
    if !is_root() {
        panic!(
            "integration-kernel-tests require elevated privileges; rerun using sudo or an elevated shell"
        );
    }

    let any_required_tool = ["nft", "iptables", "bpftool"]
        .iter()
        .any(|bin| command_exists(bin));

    if !any_required_tool && strict_mode() {
        panic!("kernel integration harness requires at least one of nft/iptables/bpftool in PATH");
    }
}

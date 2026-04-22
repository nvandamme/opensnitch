use nix::libc;

use crate::utils::command_path::resolve_command_path;

pub(super) fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub(super) fn opt_in_enabled() -> bool {
    // Elevated runs (sudo/pkexec) should automatically opt into kernel IT.
    if is_root() {
        return true;
    }
    // New canonical gate.
    if std::env::var("OPENSNITCH_RUN_PRIVILEGED_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return true;
    }
    // Compatibility aliases for existing local scripts/configs.
    if std::env::var("OPENSNITCH_RUN_PRIVILEDGED_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return true;
    }
    false
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
    if skip_if_not_opted_in() {
        return;
    }

    if !is_root() {
        panic!(
            "integration-kernel-tests require elevated privileges; rerun using sudo or an elevated shell"
        );
    }

    let any_required_tool = ["nft", "iptables", "bpftool"]
        .iter()
        .any(|bin| resolve_command_path(bin).is_some());

    if !any_required_tool && strict_mode() {
        panic!("kernel integration harness requires at least one of nft/iptables/bpftool in PATH");
    }
}

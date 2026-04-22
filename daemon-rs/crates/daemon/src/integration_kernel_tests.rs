use std::time::Duration;

use nix::libc;

use crate::adapters::{proc_connector, socket_diag};
use crate::utils::pid_resolver;
use crate::utils::command_path::command_exists;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn opt_in_enabled() -> bool {
    std::env::var("OPENSNITCH_RUN_KERNEL_IT")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn strict_mode() -> bool {
    std::env::var("OPENSNITCH_KERNEL_IT_STRICT")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn strict_mode_requires_iptables() -> bool {
    std::env::var("OPENSNITCH_KERNEL_IT_REQUIRE_IPTABLES")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn skip_if_not_opted_in() -> bool {
    if !opt_in_enabled() {
        return true;
    }
    false
}

fn skip_if_not_root() -> bool {
    if !is_root() {
        return true;
    }
    false
}

#[test]
fn kernel_harness_preflight() {
    if skip_if_not_opted_in() {
        return;
    }

    let any_required_tool = ["nft", "iptables", "bpftool"]
        .iter()
        .any(|bin| command_exists(bin));

    if !any_required_tool && strict_mode() {
        panic!("kernel integration harness requires at least one of nft/iptables/bpftool in PATH");
    }
}

#[test]
fn socket_diag_readonly_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let result = socket_diag::dump_sockets(0, 0);
    if let Err(err) = result
        && strict_mode()
    {
        panic!("socket diag smoke test failed in strict mode: {err}");
    }
}

#[test]
fn proc_connector_readonly_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let socket = match proc_connector::open_proc_events() {
        Ok(socket) => socket,
        Err(err) => {
            if strict_mode() {
                panic!("proc connector open failed in strict mode: {err}");
            }
            return;
        }
    };

    let recv_result = socket.recv_pid_event(Duration::from_millis(25));
    if let Err(err) = recv_result
        && strict_mode()
    {
        panic!("proc connector recv failed in strict mode: {err}");
    }
}

#[test]
fn pid_resolver_non_panicking_smoke() {
    if skip_if_not_opted_in() {
        return;
    }

    let _ = pid_resolver::resolve_pid_by_inode(0);
}

#[tokio::test]
async fn iptables_nfqueue_rules_privileged_smoke() {
    if skip_if_not_opted_in() || skip_if_not_root() {
        return;
    }
    if !command_exists("iptables") {
        if strict_mode() {
            panic!("iptables not found in strict kernel integration mode");
        }
        return;
    }

    let ensure_res = crate::adapters::firewall_iptables::ensure(0, true).await;
    if let Err(err) = &ensure_res {
        if strict_mode() {
            if strict_mode_requires_iptables() {
                panic!("iptables ensure failed in strict mode: {err}");
            }
            eprintln!(
                "iptables ensure unavailable in strict mode but tolerated (set OPENSNITCH_KERNEL_IT_REQUIRE_IPTABLES=1 to enforce): {err}"
            );
            return;
        }
    }

    // Always attempt cleanup if ensure succeeded.
    if ensure_res.is_ok() {
        let disable_res = crate::adapters::firewall_iptables::disable(0, true).await;
        if let Err(err) = disable_res
            && strict_mode()
        {
            if strict_mode_requires_iptables() {
                panic!("iptables disable failed in strict mode: {err}");
            }
            eprintln!(
                "iptables disable unavailable in strict mode but tolerated (set OPENSNITCH_KERNEL_IT_REQUIRE_IPTABLES=1 to enforce): {err}"
            );
        }
    }
}

#[tokio::test]
async fn nftables_nfqueue_rules_privileged_smoke() {
    if skip_if_not_opted_in() || skip_if_not_root() {
        return;
    }
    if !command_exists("nft") {
        if strict_mode() {
            panic!("nft not found in strict kernel integration mode");
        }
        return;
    }

    let ensure_res = crate::adapters::firewall_nft::ensure(0, true).await;
    if let Err(err) = &ensure_res {
        if strict_mode() {
            panic!("nft ensure failed in strict mode: {err}");
        }
    }

    if ensure_res.is_ok() {
        let disable_res = crate::adapters::firewall_nft::disable().await;
        if let Err(err) = disable_res
            && strict_mode()
        {
            panic!("nft disable failed in strict mode: {err}");
        }
    }
}

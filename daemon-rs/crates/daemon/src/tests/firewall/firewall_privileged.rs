use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue,
};
use crate::tests::gates::{
    skip_if_not_opted_in, skip_if_not_root, strict_mode, strict_mode_requires_iptables,
};
use crate::utils::command_path::resolve_command_path;
use std::sync::{Mutex, OnceLock};
use tokio::process::Command;

fn privileged_test_guard() -> &'static Mutex<()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| Mutex::new(()))
}

fn lock_privileged_test_guard() -> std::sync::MutexGuard<'static, ()> {
    privileged_test_guard()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn nft_list_chain(family: &str, table: &str, chain: &str) -> Option<String> {
    let out = Command::new("nft")
        .args(["-a", "list", "chain", family, table, chain])
        .output()
        .await
        .ok()?;

    if !out.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn make_privileged_sysfw_rule() -> FirewallConfig {
    FirewallConfig {
        enabled: true,
        version: 1,
        rules: Vec::new(),
        chains: vec![FirewallChain {
            name: "mangle_output".to_string(),
            table: "opensnitch".to_string(),
            family: "inet".to_string(),
            priority: "0".to_string(),
            r#type: "filter".to_string(),
            hook: "output".to_string(),
            policy: "accept".to_string(),
            rules: vec![FirewallRule {
                uuid: "it-sysfw-uuid-1".to_string(),
                enabled: true,
                expressions: vec![FirewallExpression {
                    statement: Some(FirewallStatement {
                        op: "==".to_string(),
                        name: "meta".to_string(),
                        values: vec![FirewallStatementValue {
                            key: "l4proto".to_string(),
                            value: "tcp".to_string(),
                        }],
                    }),
                }],
                target: "accept".to_string(),
                ..Default::default()
            }],
        }],
        zones: Vec::new(),
    }
}

#[tokio::test]
async fn iptables_nfqueue_rules_privileged_smoke() {
    let _guard = lock_privileged_test_guard();

    if skip_if_not_opted_in() {
        return;
    }
    if skip_if_not_root() {
        panic!(
            "iptables privileged test requires elevated privileges; rerun using sudo or an elevated shell"
        );
    }
    if resolve_command_path("iptables").is_none() {
        if strict_mode() {
            panic!("iptables not found in strict kernel integration mode");
        }
        return;
    }

    let ensure_res =
        crate::platform::adapters::firewall_iptables::FirewallIptablesAdapter::ensure(0, true)
            .await;
    if let Err(err) = &ensure_res {
        if strict_mode() {
            if strict_mode_requires_iptables() {
                panic!("iptables ensure failed in strict mode: {err}");
            }
            tracing::warn!(
                "iptables ensure unavailable in strict mode but tolerated (set OPENSNITCH_KERNEL_IT_REQUIRE_IPTABLES=1 to enforce): {err}"
            );
            return;
        }
    }

    // Always attempt cleanup if ensure succeeded.
    if ensure_res.is_ok() {
        let disable_res =
            crate::platform::adapters::firewall_iptables::FirewallIptablesAdapter::disable(0, true)
                .await;
        if let Err(err) = disable_res
            && strict_mode()
        {
            if strict_mode_requires_iptables() {
                panic!("iptables disable failed in strict mode: {err}");
            }
            tracing::warn!(
                "iptables disable unavailable in strict mode but tolerated (set OPENSNITCH_KERNEL_IT_REQUIRE_IPTABLES=1 to enforce): {err}"
            );
        }
    }
}

#[tokio::test]
async fn nftables_nfqueue_rules_privileged_smoke() {
    let _guard = lock_privileged_test_guard();

    if skip_if_not_opted_in() {
        return;
    }
    if skip_if_not_root() {
        panic!(
            "nft privileged test requires elevated privileges; rerun using sudo or an elevated shell"
        );
    }
    if resolve_command_path("nft").is_none() {
        if strict_mode() {
            panic!("nft not found in strict kernel integration mode");
        }
        return;
    }

    let ensure_res =
        crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::ensure(0, true)
            .await;
    if let Err(err) = &ensure_res {
        if strict_mode() {
            panic!("nft ensure failed in strict mode: {err}");
        }
    }

    if ensure_res.is_ok() {
        let disable_res =
            crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::disable().await;
        if let Err(err) = disable_res
            && strict_mode()
        {
            panic!("nft disable failed in strict mode: {err}");
        }
    }
}

#[tokio::test]
async fn nftables_interception_rules_present_then_removed() {
    let _guard = lock_privileged_test_guard();

    if skip_if_not_opted_in() {
        return;
    }
    if skip_if_not_root() {
        panic!(
            "nft interception privileged test requires elevated privileges; rerun using sudo or an elevated shell"
        );
    }
    if resolve_command_path("nft").is_none() {
        if strict_mode() {
            panic!("nft not found in strict kernel integration mode");
        }
        return;
    }

    let ensure_res =
        crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::ensure(0, true)
            .await;
    if let Err(err) = &ensure_res {
        if strict_mode() {
            panic!("nft ensure failed in strict mode: {err}");
        }
        return;
    }

    let input = nft_list_chain("inet", "opensnitch", "filter_input")
        .await
        .unwrap_or_default();
    let output = nft_list_chain("inet", "opensnitch", "mangle_output")
        .await
        .unwrap_or_default();

    assert!(input.contains("opensnitch-queue-dns"));
    assert!(output.contains("opensnitch-queue-connections-non-tcp"));
    assert!(output.contains("opensnitch-queue-connections-tcp-syn"));

    let disable_res =
        crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::disable().await;
    if let Err(err) = disable_res {
        if strict_mode() {
            panic!("nft disable failed in strict mode: {err}");
        }
        return;
    }

    let input_after = nft_list_chain("inet", "opensnitch", "filter_input").await;
    let output_after = nft_list_chain("inet", "opensnitch", "mangle_output").await;
    assert!(input_after.is_none());
    assert!(output_after.is_none());
}

#[tokio::test]
async fn nftables_apply_and_clear_system_firewall_rules() {
    let _guard = lock_privileged_test_guard();

    if skip_if_not_opted_in() {
        return;
    }
    if skip_if_not_root() {
        panic!(
            "nft system firewall privileged test requires elevated privileges; rerun using sudo or an elevated shell"
        );
    }
    if resolve_command_path("nft").is_none() {
        if strict_mode() {
            panic!("nft not found in strict kernel integration mode");
        }
        return;
    }

    let _ = crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::disable().await;
    let ensure_res =
        crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::ensure(0, true)
            .await;
    if let Err(err) = &ensure_res {
        if strict_mode() {
            panic!("nft ensure failed in strict mode: {err}");
        }
        return;
    }

    let sysfw = make_privileged_sysfw_rule();
    let apply_res =
        crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::apply_system_firewall(
            &sysfw, 0,
        )
        .await;
    if let Err(err) = &apply_res {
        let _ =
            crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::disable().await;
        if strict_mode() {
            panic!("nft apply system firewall failed in strict mode: {err}");
        }
        return;
    }

    let output = nft_list_chain("inet", "opensnitch", "mangle_output")
        .await
        .unwrap_or_default();
    assert!(output.contains("opensnitch-sysfw:it-sysfw-uuid-1"));

    let clear_res =
        crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::clear_system_firewall(&sysfw)
            .await;
    if let Err(err) = &clear_res {
        let _ =
            crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::disable().await;
        if strict_mode() {
            panic!("nft clear system firewall failed in strict mode: {err}");
        }
        return;
    }

    let output_after_clear = nft_list_chain("inet", "opensnitch", "mangle_output")
        .await
        .unwrap_or_default();
    assert!(!output_after_clear.contains("opensnitch-sysfw:it-sysfw-uuid-1"));

    let _ = crate::platform::adapters::firewall_nftables::FirewallNftablesAdapter::disable().await;
}

use anyhow::{Context, Result};
use opensnitch_proto::pb;
use tokio::process::Command;

use crate::utils::command_output::run_command_checked;
use crate::utils::command_path::resolve_command_path;
use crate::utils::conntrack::flush_conntrack_table;

const IPTABLES_BIN: &str = "iptables";
const IP6TABLES_BIN: &str = "ip6tables";

pub(crate) struct FirewallIptablesAdapter;

impl FirewallIptablesAdapter {
    fn table_or_default(rule: &pb::FwRule) -> &str {
        if rule.table.is_empty() {
            "filter"
        } else {
            rule.table.as_str()
        }
    }

    fn chain_or_default(rule: &pb::FwRule) -> &str {
        if rule.chain.is_empty() {
            "OUTPUT"
        } else {
            rule.chain.as_str()
        }
    }

    fn iptables_args(rule: &pb::FwRule) -> Vec<&str> {
        let mut args = vec![
            "-t",
            Self::table_or_default(rule),
            Self::chain_or_default(rule),
        ];
        if !rule.parameters.is_empty() {
            for part in rule.parameters.split_whitespace() {
                args.push(part);
            }
        }
        if !rule.target.is_empty() {
            args.push("-j");
            args.push(rule.target.as_str());
        }
        if !rule.target_parameters.is_empty() {
            for part in rule.target_parameters.split_whitespace() {
                args.push(part);
            }
        }
        args
    }

    fn nfqueue_rules(queue_num: &str, queue_bypass: bool) -> (Vec<&str>, Vec<&str>) {
        let mut conn_rule = vec![
            "-t",
            "mangle",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,RELATED",
            "-j",
            "NFQUEUE",
            "--queue-num",
            queue_num,
        ];
        if queue_bypass {
            conn_rule.push("--queue-bypass");
        }

        let mut dns_rule = vec![
            "INPUT",
            "-p",
            "udp",
            "--sport",
            "53",
            "-j",
            "NFQUEUE",
            "--queue-num",
            queue_num,
        ];
        if queue_bypass {
            dns_rule.push("--queue-bypass");
        }

        (conn_rule, dns_rule)
    }

    fn chain_policy_args(chain: &pb::FwChain) -> Option<Vec<String>> {
        if chain.hook.trim().is_empty() || chain.r#type.trim().is_empty() {
            return None;
        }

        let table = chain.r#type.trim();
        let hook = chain.hook.trim().to_uppercase();
        let policy = if chain.policy.trim().is_empty() {
            "ACCEPT".to_string()
        } else {
            chain.policy.trim().to_uppercase()
        };

        Some(vec![
            "-w".to_string(),
            "-t".to_string(),
            table.to_string(),
            "-P".to_string(),
            hook,
            policy,
        ])
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_chain_policy_args(chain: &pb::FwChain) -> Option<Vec<String>> {
        Self::chain_policy_args(chain)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_iptables_args(rule: &pb::FwRule) -> Vec<String> {
        Self::iptables_args(rule)
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_nfqueue_rules(
        queue_num: &str,
        queue_bypass: bool,
    ) -> (Vec<String>, Vec<String>) {
        let (conn, dns) = Self::nfqueue_rules(queue_num, queue_bypass);
        (
            conn.into_iter().map(ToOwned::to_owned).collect(),
            dns.into_iter().map(ToOwned::to_owned).collect(),
        )
    }
}

impl FirewallIptablesAdapter {
    async fn apply_nfqueue_rules(queue_num: &str, queue_bypass: bool, ensure: bool) -> Result<()> {
        let (conn_rule, dns_rule) = Self::nfqueue_rules(queue_num, queue_bypass);

        for bin in Self::active_bins() {
            if ensure {
                Self::ensure_rule(bin, &conn_rule)
                    .await
                    .with_context(|| format!("{bin} connection NFQUEUE rule"))?;
                Self::ensure_rule(bin, &dns_rule)
                    .await
                    .with_context(|| format!("{bin} DNS NFQUEUE rule"))?;
            } else {
                Self::delete_rule(bin, &conn_rule).await?;
                Self::delete_rule(bin, &dns_rule).await?;
            }
        }

        Ok(())
    }

    pub async fn ensure(queue_num: u16, queue_bypass: bool) -> Result<()> {
        let queue_num = queue_num.to_string();
        Self::apply_nfqueue_rules(queue_num.as_str(), queue_bypass, true).await?;

        Self::flush_conntrack().await;

        Ok(())
    }

    pub async fn disable(queue_num: u16, queue_bypass: bool) -> Result<()> {
        let queue_num = queue_num.to_string();
        Self::apply_nfqueue_rules(queue_num.as_str(), queue_bypass, false).await?;

        Ok(())
    }

    pub async fn interception_rules_valid(queue_num: u16, queue_bypass: bool) -> Result<bool> {
        if resolve_command_path(IPTABLES_BIN).is_none() {
            return Ok(false);
        }

        let queue_num = queue_num.to_string();
        let queue_num = queue_num.as_str();
        let (conn_rule, dns_rule) = Self::nfqueue_rules(queue_num, queue_bypass);

        let ipv4_conn = Self::check_rule_exists(IPTABLES_BIN, &conn_rule).await?;
        let ipv4_dns = Self::check_rule_exists(IPTABLES_BIN, &dns_rule).await?;
        let mut healthy = ipv4_conn && ipv4_dns;

        if resolve_command_path(IP6TABLES_BIN).is_some() {
            let ipv6_conn = Self::check_rule_exists(IP6TABLES_BIN, &conn_rule).await?;
            let ipv6_dns = Self::check_rule_exists(IP6TABLES_BIN, &dns_rule).await?;
            healthy = healthy && ipv6_conn && ipv6_dns;
        }

        Ok(healthy)
    }

    pub async fn apply_system_firewall(sysfw: &pb::SysFirewall) -> Result<()> {
        if !sysfw.enabled {
            return Ok(());
        }

        for item in &sysfw.system_rules {
            for chain in &item.chains {
                Self::ensure_chain_policy(chain).await?;
            }

            if let Some(rule) = &item.rule {
                if !rule.enabled {
                    continue;
                }
                Self::ensure_system_rule(rule).await?;
            }
        }

        Ok(())
    }

    pub async fn clear_system_firewall(sysfw: &pb::SysFirewall) -> Result<()> {
        for item in &sysfw.system_rules {
            if let Some(rule) = &item.rule {
                Self::delete_system_rule(rule).await?;
            }
        }

        Ok(())
    }

    async fn ensure_rule(bin: &str, rule: &[&str]) -> Result<()> {
        if Self::check_rule_exists(bin, rule).await? {
            return Ok(());
        }

        let mut add_args = vec!["-w", "-I"];
        add_args.extend_from_slice(rule);

        run_command_checked(bin, &add_args, &format!("run {bin} to add NFQUEUE rule")).await?;

        Ok(())
    }

    async fn check_rule_exists(bin: &str, rule: &[&str]) -> Result<bool> {
        let mut check_args = vec!["-w", "-C"];
        check_args.extend_from_slice(rule);

        let out = Command::new(bin)
            .args(&check_args)
            .output()
            .await
            .with_context(|| format!("run {bin} to check existing NFQUEUE rule"))?;

        Ok(out.status.success())
    }

    async fn delete_rule(bin: &str, rule: &[&str]) -> Result<()> {
        while Self::check_rule_exists(bin, rule).await? {
            let mut del_args = vec!["-w", "-D"];
            del_args.extend_from_slice(rule);

            run_command_checked(bin, &del_args, &format!("run {bin} to delete NFQUEUE rule"))
                .await?;
        }

        Ok(())
    }

    /// Returns `[IPTABLES_BIN]` or `[IPTABLES_BIN, IP6TABLES_BIN]` depending on
    /// whether ip6tables is available at runtime.
    fn active_bins() -> &'static [&'static str] {
        if resolve_command_path(IP6TABLES_BIN).is_some() {
            &[IPTABLES_BIN, IP6TABLES_BIN]
        } else {
            &[IPTABLES_BIN]
        }
    }

    async fn flush_conntrack() {
        let _ = flush_conntrack_table().await;
    }

    async fn apply_system_rule_with(rule: &pb::FwRule, ensure: bool) -> Result<()> {
        let args = Self::iptables_args(rule);
        for bin in Self::active_bins() {
            if ensure {
                Self::ensure_rule(bin, &args).await?;
            } else {
                Self::delete_rule(bin, &args).await?;
            }
        }
        Ok(())
    }

    async fn ensure_system_rule(rule: &pb::FwRule) -> Result<()> {
        Self::apply_system_rule_with(rule, true).await
    }

    async fn delete_system_rule(rule: &pb::FwRule) -> Result<()> {
        Self::apply_system_rule_with(rule, false).await
    }

    async fn ensure_chain_policy(chain: &pb::FwChain) -> Result<()> {
        let Some(args) = Self::chain_policy_args(chain) else {
            return Ok(());
        };
        let args_ref = args.iter().map(String::as_str).collect::<Vec<_>>();
        for bin in Self::active_bins() {
            let ctx = format!("{bin} chain policy update");
            run_command_checked(bin, &args_ref, &ctx).await?;
        }
        Ok(())
    }
}

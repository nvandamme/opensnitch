use anyhow::{Context, Result, bail};
use opensnitch_proto::pb;
use tokio::process::Command;

use crate::utils::command_path::command_exists;

const IPTABLES_BIN: &str = "iptables";
const IP6TABLES_BIN: &str = "ip6tables";

trait FwRuleIptExt {
    fn table_or_default(&self) -> &str;
    fn chain_or_default(&self) -> &str;
    fn iptables_args(&self) -> Vec<&str>;
}

impl FwRuleIptExt for pb::FwRule {
    fn table_or_default(&self) -> &str {
        if self.table.is_empty() {
            "filter"
        } else {
            self.table.as_str()
        }
    }

    fn chain_or_default(&self) -> &str {
        if self.chain.is_empty() {
            "OUTPUT"
        } else {
            self.chain.as_str()
        }
    }

    fn iptables_args(&self) -> Vec<&str> {
        let mut args = vec!["-t", self.table_or_default(), self.chain_or_default()];
        if !self.parameters.is_empty() {
            for part in self.parameters.split_whitespace() {
                args.push(part);
            }
        }
        if !self.target.is_empty() {
            args.push("-j");
            args.push(self.target.as_str());
        }
        if !self.target_parameters.is_empty() {
            for part in self.target_parameters.split_whitespace() {
                args.push(part);
            }
        }
        args
    }
}

trait QueueNumIptExt {
    fn nfqueue_rules(&self, queue_bypass: bool) -> (Vec<&str>, Vec<&str>);
}

impl QueueNumIptExt for str {
    fn nfqueue_rules(&self, queue_bypass: bool) -> (Vec<&str>, Vec<&str>) {
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
            self,
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
            self,
        ];
        if queue_bypass {
            dns_rule.push("--queue-bypass");
        }

        (conn_rule, dns_rule)
    }
}

pub async fn ensure(queue_num: u16, queue_bypass: bool) -> Result<()> {
    let queue_num = queue_num.to_string();
    let queue_num = queue_num.as_str();
    let (conn_rule, dns_rule) = queue_num.nfqueue_rules(queue_bypass);

    ensure_rule(IPTABLES_BIN, &conn_rule)
        .await
        .context("ensure IPv4 connection NFQUEUE rule")?;
    ensure_rule(IPTABLES_BIN, &dns_rule)
        .await
        .context("ensure IPv4 DNS NFQUEUE rule")?;

    if command_exists(IP6TABLES_BIN) {
        ensure_rule(IP6TABLES_BIN, &conn_rule)
            .await
            .context("ensure IPv6 connection NFQUEUE rule")?;
        ensure_rule(IP6TABLES_BIN, &dns_rule)
            .await
            .context("ensure IPv6 DNS NFQUEUE rule")?;
    }

    flush_conntrack().await;

    Ok(())
}

pub async fn disable(queue_num: u16, queue_bypass: bool) -> Result<()> {
    let queue_num = queue_num.to_string();
    let queue_num = queue_num.as_str();
    let (conn_rule, dns_rule) = queue_num.nfqueue_rules(queue_bypass);

    delete_rule(IPTABLES_BIN, &conn_rule).await?;
    delete_rule(IPTABLES_BIN, &dns_rule).await?;

    if command_exists(IP6TABLES_BIN) {
        delete_rule(IP6TABLES_BIN, &conn_rule).await?;
        delete_rule(IP6TABLES_BIN, &dns_rule).await?;
    }

    Ok(())
}

pub async fn interception_rules_valid(queue_num: u16, queue_bypass: bool) -> Result<bool> {
    if !command_exists(IPTABLES_BIN) {
        return Ok(false);
    }

    let queue_num = queue_num.to_string();
    let queue_num = queue_num.as_str();
    let (conn_rule, dns_rule) = queue_num.nfqueue_rules(queue_bypass);

    let ipv4_conn = check_rule_exists(IPTABLES_BIN, &conn_rule).await?;
    let ipv4_dns = check_rule_exists(IPTABLES_BIN, &dns_rule).await?;
    let mut healthy = ipv4_conn && ipv4_dns;

    if command_exists(IP6TABLES_BIN) {
        let ipv6_conn = check_rule_exists(IP6TABLES_BIN, &conn_rule).await?;
        let ipv6_dns = check_rule_exists(IP6TABLES_BIN, &dns_rule).await?;
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
            ensure_chain_policy(chain).await?;
        }

        if let Some(rule) = &item.rule {
            if !rule.enabled {
                continue;
            }
            ensure_system_rule(rule).await?;
        }
    }

    Ok(())
}

pub async fn clear_system_firewall(sysfw: &pb::SysFirewall) -> Result<()> {
    for item in &sysfw.system_rules {
        if let Some(rule) = &item.rule {
            delete_system_rule(rule).await?;
        }
    }

    Ok(())
}

async fn ensure_rule(bin: &str, rule: &[&str]) -> Result<()> {
    if check_rule_exists(bin, rule).await? {
        return Ok(());
    }

    let mut add_args = vec!["-w", "-I"];
    add_args.extend_from_slice(rule);

    let out = Command::new(bin)
        .args(&add_args)
        .output()
        .await
        .with_context(|| format!("run {bin} to add NFQUEUE rule"))?;

    if !out.status.success() {
        bail!(
            "{bin} add rule failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

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
    while check_rule_exists(bin, rule).await? {
        let mut del_args = vec!["-w", "-D"];
        del_args.extend_from_slice(rule);

        let out = Command::new(bin)
            .args(&del_args)
            .output()
            .await
            .with_context(|| format!("run {bin} to delete NFQUEUE rule"))?;

        if !out.status.success() {
            bail!(
                "{bin} delete rule failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    Ok(())
}

async fn flush_conntrack() {
    if !command_exists("conntrack") {
        return;
    }

    let _ = Command::new("conntrack").args(["-F"]).status().await;
}

async fn ensure_system_rule(rule: &pb::FwRule) -> Result<()> {
    let args = rule.iptables_args();

    ensure_rule(IPTABLES_BIN, &args).await?;
    if command_exists(IP6TABLES_BIN) {
        ensure_rule(IP6TABLES_BIN, &args).await?;
    }

    Ok(())
}

async fn delete_system_rule(rule: &pb::FwRule) -> Result<()> {
    let args = rule.iptables_args();

    delete_rule(IPTABLES_BIN, &args).await?;
    if command_exists(IP6TABLES_BIN) {
        delete_rule(IP6TABLES_BIN, &args).await?;
    }

    Ok(())
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

async fn ensure_chain_policy(chain: &pb::FwChain) -> Result<()> {
    let Some(args) = chain_policy_args(chain) else {
        return Ok(());
    };

    let args_ref = args.iter().map(String::as_str).collect::<Vec<_>>();
    let out = Command::new(IPTABLES_BIN)
        .args(&args_ref)
        .output()
        .await
        .context("run iptables chain policy update")?;

    if !out.status.success() {
        bail!(
            "iptables chain policy update failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    if command_exists(IP6TABLES_BIN) {
        let out6 = Command::new(IP6TABLES_BIN)
            .args(&args_ref)
            .output()
            .await
            .context("run ip6tables chain policy update")?;

        if !out6.status.success() {
            bail!(
                "ip6tables chain policy update failed: {}",
                String::from_utf8_lossy(&out6.stderr)
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::chain_policy_args;
    use opensnitch_proto::pb;

    #[test]
    fn chain_policy_args_builds_expected_iptables_policy_command() {
        let chain = pb::FwChain {
            r#type: "mangle".to_string(),
            hook: "output".to_string(),
            policy: "drop".to_string(),
            ..Default::default()
        };

        let args = chain_policy_args(&chain).expect("policy args expected");
        assert_eq!(args, vec!["-w", "-t", "mangle", "-P", "OUTPUT", "DROP"]);
    }

    #[test]
    fn chain_policy_args_returns_none_when_hook_or_table_missing() {
        let missing_hook = pb::FwChain {
            r#type: "filter".to_string(),
            ..Default::default()
        };
        assert!(chain_policy_args(&missing_hook).is_none());

        let missing_type = pb::FwChain {
            hook: "output".to_string(),
            ..Default::default()
        };
        assert!(chain_policy_args(&missing_type).is_none());
    }
}

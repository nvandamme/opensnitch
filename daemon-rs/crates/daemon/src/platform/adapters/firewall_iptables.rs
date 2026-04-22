use anyhow::{Context, Result};
use tokio::process::Command;

use crate::models::firewall_config::{FirewallChain, FirewallConfig, FirewallRule};
use crate::utils::command_output::run_command_checked;
use crate::utils::command_path::resolve_command_path;
use crate::utils::conntrack::flush_conntrack_table;

const IPTABLES_BIN: &str = "iptables";
const IP6TABLES_BIN: &str = "ip6tables";

pub(crate) struct FirewallIptablesAdapter;

impl FirewallIptablesAdapter {
    fn zone_name_from_chain(chain_name: &str) -> Option<String> {
        let name = chain_name.trim().to_ascii_lowercase();
        if !name.starts_with("zone_") {
            return None;
        }

        let rest = &name["zone_".len()..];
        let last_sep = rest.rfind('_')?;
        let zone = rest[..last_sep].trim();
        if zone.is_empty() {
            return None;
        }

        Some(zone.to_string())
    }

    fn upsert_chain<'a>(
        chains: &'a mut Vec<FirewallChain>,
        family: &str,
        table: &str,
        name: &str,
    ) -> &'a mut FirewallChain {
        if let Some(pos) = chains
            .iter()
            .position(|c| c.family == family && c.table == table && c.name == name)
        {
            return &mut chains[pos];
        }

        chains.push(FirewallChain {
            name: name.to_string(),
            table: table.to_string(),
            family: family.to_string(),
            hook: name.to_ascii_lowercase(),
            r#type: table.to_string(),
            ..Default::default()
        });
        let idx = chains.len() - 1;
        &mut chains[idx]
    }

    fn parse_iptables_save_dump(dump: &str, family: &str) -> FirewallConfig {
        let mut chains: Vec<FirewallChain> = Vec::new();
        let mut zones: Vec<crate::models::firewall_config::FirewallZone> = Vec::new();
        let mut current_table = String::new();

        for raw_line in dump.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(table) = line.strip_prefix('*') {
                current_table = table.trim().to_string();
                continue;
            }

            if line == "COMMIT" {
                current_table.clear();
                continue;
            }

            if let Some(def) = line.strip_prefix(':') {
                let parts = def.split_whitespace().collect::<Vec<_>>();
                if parts.len() >= 2 {
                    let chain_name = parts[0].trim();
                    let policy = parts[1].trim();
                    let chain =
                        Self::upsert_chain(&mut chains, family, current_table.as_str(), chain_name);
                    chain.policy = policy.to_ascii_lowercase();
                }
                continue;
            }

            if let Some(rule_def) = line.strip_prefix("-A ") {
                let tokens = rule_def.split_whitespace().collect::<Vec<_>>();
                if tokens.is_empty() {
                    continue;
                }

                let chain_name = tokens[0];
                let body = &tokens[1..];
                let jump_idx = body.iter().position(|t| *t == "-j");

                let (parameters, target, target_parameters) = if let Some(idx) = jump_idx {
                    let target = body.get(idx + 1).copied().unwrap_or_default().to_string();
                    let target_parameters = if idx + 2 < body.len() {
                        body[idx + 2..].join(" ")
                    } else {
                        String::new()
                    };
                    (body[..idx].join(" "), target, target_parameters)
                } else {
                    (body.join(" "), String::new(), String::new())
                };

                let chain =
                    Self::upsert_chain(&mut chains, family, current_table.as_str(), chain_name);
                chain.rules.push(FirewallRule {
                    table: current_table.clone(),
                    chain: chain_name.to_string(),
                    uuid: String::new(),
                    enabled: true,
                    position: (chain.rules.len() as u64) + 1,
                    description: String::new(),
                    parameters,
                    expressions: Vec::new(),
                    target,
                    target_parameters,
                });
            }
        }

        let mut top_level_chains = Vec::new();
        for chain in chains {
            if let Some(zone_name) = Self::zone_name_from_chain(&chain.name) {
                if let Some(existing) = zones.iter_mut().find(|z| z.name == zone_name) {
                    existing.chains.push(chain);
                } else {
                    zones.push(crate::models::firewall_config::FirewallZone {
                        name: zone_name,
                        chains: vec![chain],
                    });
                }
            } else {
                top_level_chains.push(chain);
            }
        }

        FirewallConfig {
            enabled: true,
            version: 0,
            rules: Vec::new(),
            chains: top_level_chains,
            zones,
        }
    }

    #[allow(dead_code)]
    fn merge_extracted_config(dst: &mut FirewallConfig, src: FirewallConfig) {
        dst.chains.extend(src.chains);
        for src_zone in src.zones {
            if let Some(existing) = dst.zones.iter_mut().find(|z| z.name == src_zone.name) {
                existing.chains.extend(src_zone.chains);
            } else {
                dst.zones.push(src_zone);
            }
        }
    }

    #[allow(dead_code)]
    async fn capture_save_dump(bin: &str) -> Result<String> {
        let save_bin = format!("{bin}-save");
        let out = Command::new(&save_bin)
            .output()
            .await
            .with_context(|| format!("capture {save_bin} rules for DTO extraction"))?;

        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "{bin} rules extraction failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    fn table_or_default(rule: &FirewallRule) -> &str {
        if rule.table.is_empty() {
            "filter"
        } else {
            rule.table.as_str()
        }
    }

    fn chain_or_default(rule: &FirewallRule) -> &str {
        if rule.chain.is_empty() {
            "OUTPUT"
        } else {
            rule.chain.as_str()
        }
    }

    fn iptables_args(rule: &FirewallRule) -> Vec<&str> {
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

    fn chain_policy_args(chain: &FirewallChain) -> Option<Vec<String>> {
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
    pub(crate) fn probe_chain_policy_args(chain: &FirewallChain) -> Option<Vec<String>> {
        Self::chain_policy_args(chain)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_iptables_args(rule: &FirewallRule) -> Vec<String> {
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_iptables_save_dump(dump: &str, family: &str) -> FirewallConfig {
        Self::parse_iptables_save_dump(dump, family)
    }
}

impl FirewallIptablesAdapter {
    #[allow(dead_code)]
    pub async fn extract_system_firewall() -> Result<FirewallConfig> {
        if resolve_command_path(IPTABLES_BIN).is_none() {
            return Err(anyhow::anyhow!("iptables binary not found"));
        }

        let mut merged = FirewallConfig {
            enabled: true,
            ..Default::default()
        };

        let ipv4_dump = Self::capture_save_dump(IPTABLES_BIN).await?;
        let ipv4 = Self::parse_iptables_save_dump(&ipv4_dump, "ip");
        Self::merge_extracted_config(&mut merged, ipv4);

        if resolve_command_path(IP6TABLES_BIN).is_some() {
            let ipv6_dump = Self::capture_save_dump(IP6TABLES_BIN).await?;
            let ipv6 = Self::parse_iptables_save_dump(&ipv6_dump, "ip6");
            Self::merge_extracted_config(&mut merged, ipv6);
        }

        Ok(merged)
    }

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

    pub async fn apply_system_firewall(sysfw: &FirewallConfig) -> Result<()> {
        if !sysfw.enabled {
            return Ok(());
        }

        for chain in &sysfw.chains {
            Self::ensure_chain_policy(chain).await?;

            for rule in &chain.rules {
                if !rule.enabled {
                    continue;
                }
                Self::ensure_system_rule(rule).await?;
            }
        }

        for rule in &sysfw.rules {
            if !rule.enabled {
                continue;
            }
            Self::ensure_system_rule(rule).await?;
        }

        for zone in &sysfw.zones {
            for chain in &zone.chains {
                Self::ensure_chain_policy(chain).await?;

                for rule in &chain.rules {
                    if !rule.enabled {
                        continue;
                    }
                    Self::ensure_system_rule(rule).await?;
                }
            }
        }

        Ok(())
    }

    pub async fn clear_system_firewall(sysfw: &FirewallConfig) -> Result<()> {
        for chain in &sysfw.chains {
            for rule in &chain.rules {
                Self::delete_system_rule(rule).await?;
            }
        }

        for rule in &sysfw.rules {
            Self::delete_system_rule(rule).await?;
        }

        for zone in &sysfw.zones {
            for chain in &zone.chains {
                for rule in &chain.rules {
                    Self::delete_system_rule(rule).await?;
                }
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

    async fn apply_system_rule_with(rule: &FirewallRule, ensure: bool) -> Result<()> {
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

    async fn ensure_system_rule(rule: &FirewallRule) -> Result<()> {
        Self::apply_system_rule_with(rule, true).await
    }

    async fn delete_system_rule(rule: &FirewallRule) -> Result<()> {
        Self::apply_system_rule_with(rule, false).await
    }

    async fn ensure_chain_policy(chain: &FirewallChain) -> Result<()> {
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

use anyhow::{Context, Result, bail};
use opensnitch_proto::pb;
use tokio::process::Command;

use crate::utils::command_path::resolve_command_path;
use crate::utils::conntrack::flush_conntrack_table;
use crate::utils::name_parsing::case_folded;

const SYSFW_TAG_PREFIX: &str = "opensnitch-sysfw:";

pub(crate) struct FirewallNftAdapter;

#[derive(Debug, Clone, Copy)]
struct NftInterceptionRuleCounts {
    dns_count: usize,
    non_tcp_count: usize,
    tcp_syn_count: usize,
}

impl NftInterceptionRuleCounts {
    fn valid(self) -> bool {
        self.dns_count == 1 && self.non_tcp_count == 1 && self.tcp_syn_count == 1
    }

    fn detail(self) -> String {
        format!(
            "expected exactly one tagged interception rule for each class; observed dns={}, non_tcp={}, tcp_syn={}",
            self.dns_count, self.non_tcp_count, self.tcp_syn_count
        )
    }
}

impl FirewallNftAdapter {
    fn family_or_default(chain: &pb::FwChain) -> &str {
        if chain.family.is_empty() {
            "inet"
        } else {
            chain.family.as_str()
        }
    }

    fn table_or_default(chain: &pb::FwChain) -> &str {
        if chain.table.is_empty() {
            "opensnitch"
        } else {
            chain.table.as_str()
        }
    }

    fn chain_name_or_default(chain: &pb::FwChain) -> &str {
        if chain.name.is_empty() {
            "mangle_output"
        } else {
            chain.name.as_str()
        }
    }

    fn rule_tag(chain: &pb::FwChain, rule: &pb::FwRule) -> String {
        let id = if !rule.uuid.is_empty() {
            rule.uuid.clone()
        } else {
            format!(
                "{}:{}:{}:{}",
                Self::table_or_default(chain),
                Self::chain_name_or_default(chain),
                rule.position,
                rule.description
            )
        };
        format!("{SYSFW_TAG_PREFIX}{id}")
    }

    fn nft_expression(rule: &pb::FwRule, queue_num: u16) -> String {
        if !rule.parameters.is_empty() {
            let mut out = Self::normalize_nft_parameters(&rule.parameters);
            if !rule.target.is_empty() {
                out.push(' ');
                out.push_str(&rule.target);
            }
            if !rule.target_parameters.is_empty() {
                out.push(' ');
                out.push_str(&rule.target_parameters);
            }
            return Self::normalize_nft_parameters(&out);
        }

        let mut parts: Vec<String> = Vec::new();
        for expr in &rule.expressions {
            let Some(statement) = &expr.statement else {
                continue;
            };
            let name = statement.name.trim();
            if name.is_empty() {
                continue;
            }
            for value in &statement.values {
                if value.key.trim().is_empty() {
                    continue;
                }
                let op = if statement.op.trim().is_empty() {
                    ""
                } else {
                    statement.op.trim()
                };
                if op.is_empty() {
                    parts.push(format!("{} {} {}", name, value.key, value.value));
                } else {
                    parts.push(format!("{} {} {} {}", name, value.key, op, value.value));
                }
            }
        }

        if !rule.target.is_empty() {
            parts.push(rule.target.to_string());
        }

        if !rule.target_parameters.is_empty() {
            let mut target_params = rule.target_parameters.clone();
            if case_folded(&rule.target) == "queue"
                && target_params.contains("num 0")
                && queue_num != 0
            {
                target_params = target_params.replace("num 0", &format!("num {queue_num}"));
            }
            parts.push(target_params);
        }

        Self::normalize_nft_parameters(&parts.join(" "))
    }

    fn nft_rule_lines(value: &str) -> Vec<&str> {
        value
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("# handle "))
            .collect()
    }

    fn parse_nft_handle(line: &str) -> Option<String> {
        line.split("# handle ")
            .nth(1)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    fn nft_rule_tag(rule_expr: &str) -> &str {
        if rule_expr.contains("opensnitch-queue-dns") {
            "opensnitch-queue-dns"
        } else if rule_expr.contains("opensnitch-queue-connections-non-tcp") {
            "opensnitch-queue-connections-non-tcp"
        } else if rule_expr.contains("opensnitch-queue-connections-tcp-syn") {
            "opensnitch-queue-connections-tcp-syn"
        } else {
            "opensnitch-queue-connections"
        }
    }

    fn normalize_nft_parameters(parameters: &str) -> String {
        let out = Self::normalize_nft_type_list(parameters, "icmp type");
        let out = Self::normalize_nft_type_list(&out, "icmpv6 type");
        let out = Self::normalize_l4proto_list(&out);
        Self::normalize_transport_ports(&out)
    }

    fn normalize_l4proto_list(parameters: &str) -> String {
        for marker in ["meta l4proto ==", "meta l4proto"] {
            if let Some((prefix, _, values, suffix)) =
                Self::try_expand_csv_token(parameters, marker)
            {
                return format!("{prefix}meta l4proto {{ {} }}{suffix}", values.join(", "));
            }
        }
        parameters.to_string()
    }

    fn normalize_transport_ports(parameters: &str) -> String {
        parameters
            .replace("meta dport ==", "th dport")
            .replace("meta sport ==", "th sport")
            .replace("meta dport", "th dport")
            .replace("meta sport", "th sport")
            .replace("th dport ==", "th dport")
            .replace("th sport ==", "th sport")
    }

    /// Find `marker` in `parameters`, extract the whitespace-delimited token that
    /// follows it, and split it on commas.  Returns `None` when the marker is
    /// absent, the token is already brace-wrapped, or fewer than two values exist.
    /// Returns `(prefix, between_ws, values, suffix)` otherwise.
    fn try_expand_csv_token<'a>(
        parameters: &'a str,
        marker: &str,
    ) -> Option<(&'a str, &'a str, Vec<&'a str>, &'a str)> {
        let marker_start = parameters.find(marker)?;
        let values_start = marker_start + marker.len();
        let after_marker = &parameters[values_start..];
        let trimmed = after_marker.trim_start();
        let leading_ws_len = after_marker.len() - trimmed.len();
        let token_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        let token = &trimmed[..token_end];

        if !token.contains(',') || token.starts_with('{') {
            return None;
        }

        let values: Vec<&str> = token
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect();

        if values.len() < 2 {
            return None;
        }

        let prefix = &parameters[..marker_start];
        let between = &after_marker[..leading_ws_len];
        let suffix = &trimmed[token_end..];
        Some((prefix, between, values, suffix))
    }

    fn normalize_nft_type_list(parameters: &str, marker: &str) -> String {
        let Some((prefix, between, values, suffix)) =
            Self::try_expand_csv_token(parameters, marker)
        else {
            return parameters.to_string();
        };
        format!(
            "{prefix}{marker}{between}{{ {} }}{suffix}",
            values.join(", ")
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_family_or_default(chain: &pb::FwChain) -> &str {
        Self::family_or_default(chain)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_table_or_default(chain: &pb::FwChain) -> &str {
        Self::table_or_default(chain)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_chain_name_or_default(chain: &pb::FwChain) -> &str {
        Self::chain_name_or_default(chain)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_rule_tag(chain: &pb::FwChain, rule: &pb::FwRule) -> String {
        Self::rule_tag(chain, rule)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_nft_expression(rule: &pb::FwRule, queue_num: u16) -> String {
        Self::nft_expression(rule, queue_num)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_nft_rule_lines(value: &str) -> Vec<&str> {
        Self::nft_rule_lines(value)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_parse_nft_handle(line: &str) -> Option<String> {
        Self::parse_nft_handle(line)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn probe_nft_rule_tag(rule_expr: &str) -> &str {
        Self::nft_rule_tag(rule_expr)
    }
}

impl FirewallNftAdapter {
    pub async fn ensure(queue_num: u16, queue_bypass: bool) -> Result<()> {
        if resolve_command_path("nft").is_none() {
            bail!("nft binary not found");
        }

        let queue_num = queue_num.to_string();
        let bypass = if queue_bypass { " bypass" } else { "" };

        Self::run_nft(&["add", "table", "inet", "opensnitch"])
            .await
            .ok();
        Self::ensure_chain_with_fallback(
            "inet",
            "opensnitch",
            "filter_input",
            "input",
            "0",
            "accept",
            &["filter"],
        )
        .await?;
        Self::ensure_chain_with_fallback(
            "inet",
            "opensnitch",
            "mangle_output",
            "output",
            "0",
            "accept",
            &["route", "filter"],
        )
        .await?;

        if !Self::interception_rules_valid_impl().await? {
            Self::delete_interception_rules().await.ok();
        }

        Self::ensure_rule(
            "inet opensnitch filter_input",
            &format!(
                "udp sport 53 queue num {}{} comment \"opensnitch-queue-dns\"",
                queue_num, bypass
            ),
        )
        .await?;
        Self::ensure_rule(
            "inet opensnitch mangle_output",
            &format!(
                "meta l4proto != tcp ct state new,related queue num {}{} comment \"opensnitch-queue-connections-non-tcp\"",
                queue_num, bypass
            ),
        )
        .await?;
        Self::ensure_rule(
            "inet opensnitch mangle_output",
            &format!(
                "tcp flags & (fin|syn|rst|ack) == syn queue num {}{} comment \"opensnitch-queue-connections-tcp-syn\"",
                queue_num, bypass
            ),
        )
        .await?;

        Self::flush_conntrack().await;

        Ok(())
    }

    pub async fn disable() -> Result<()> {
        if resolve_command_path("nft").is_none() {
            return Ok(());
        }

        let _ = Self::run_nft(&["delete", "table", "inet", "opensnitch"]).await;
        Ok(())
    }

    pub async fn interception_rules_valid() -> Result<bool> {
        if resolve_command_path("nft").is_none() {
            return Ok(false);
        }

        Self::interception_rules_valid_impl().await
    }

    pub async fn interception_rules_health_report(
    ) -> Result<crate::platform::ports::firewall_port::InterceptionHealth> {
        if resolve_command_path("nft").is_none() {
            return Ok(crate::platform::ports::firewall_port::InterceptionHealth {
                valid: false,
                detail: Some("nft binary not found".to_string()),
            });
        }

        let counts = Self::interception_rule_counts().await?;
        let valid = counts.valid();
        Ok(crate::platform::ports::firewall_port::InterceptionHealth {
            valid,
            detail: if valid { None } else { Some(counts.detail()) },
        })
    }

    pub async fn apply_system_firewall(sysfw: &pb::SysFirewall, queue_num: u16) -> Result<()> {
        if !sysfw.enabled {
            tracing::info!("[nftables] AddSystemRules() fw disabled");
            return Ok(());
        }

        for item in &sysfw.system_rules {
            for chain in &item.chains {
                Self::ensure_system_chain(chain).await?;

                for rule in &chain.rules {
                    if !rule.enabled {
                        continue;
                    }

                    let expr = Self::nft_expression(rule, queue_num);
                    if expr.is_empty() {
                        continue;
                    }

                    let tag = Self::rule_tag(chain, rule);
                    if Self::chain_has_tag(chain, &tag).await? {
                        continue;
                    }

                    let mut args = vec!["add", "rule"];
                    args.push(Self::family_or_default(chain));
                    args.push(Self::table_or_default(chain));
                    args.push(Self::chain_name_or_default(chain));
                    for token in expr.split_whitespace() {
                        args.push(token);
                    }
                    args.push("comment");
                    let comment = format!("\"{tag}\"");
                    args.push(comment.as_str());

                    Self::run_nft(&args).await?;
                }
            }
        }

        Ok(())
    }

    pub async fn clear_system_firewall(sysfw: &pb::SysFirewall) -> Result<()> {
        if resolve_command_path("nft").is_none() {
            return Ok(());
        }

        for item in &sysfw.system_rules {
            for chain in &item.chains {
                Self::delete_tagged_rules(chain).await?;
            }
        }

        Ok(())
    }
}

impl FirewallNftAdapter {
    async fn ensure_rule(chain: &str, rule_expr: &str) -> Result<()> {
        let parts: Vec<&str> = chain.split_whitespace().collect();
        if parts.len() == 3 {
            if let Ok(listing) = Self::list_chain(parts[0], parts[1], parts[2]).await {
                if listing.contains(FirewallNftAdapter::nft_rule_tag(rule_expr)) {
                    return Ok(());
                }
            }
        }

        let mut args = vec!["add", "rule"];
        args.extend(chain.split_whitespace());
        args.extend(rule_expr.split_whitespace());

        Self::run_nft(&args).await
    }

    async fn interception_rules_valid_impl() -> Result<bool> {
        Ok(Self::interception_rule_counts().await?.valid())
    }

    async fn interception_rule_counts() -> Result<NftInterceptionRuleCounts> {
        let input = Self::list_chain("inet", "opensnitch", "filter_input").await?;
        let output = Self::list_chain("inet", "opensnitch", "mangle_output").await?;

        let input_rules = FirewallNftAdapter::nft_rule_lines(&input);
        let output_rules = FirewallNftAdapter::nft_rule_lines(&output);

        Ok(NftInterceptionRuleCounts {
            dns_count: Self::count_rules_with_tag(&input_rules, "opensnitch-queue-dns"),
            non_tcp_count: Self::count_rules_with_tag(
                &output_rules,
                "opensnitch-queue-connections-non-tcp",
            ),
            tcp_syn_count: Self::count_rules_with_tag(
                &output_rules,
                "opensnitch-queue-connections-tcp-syn",
            ),
        })
    }

    fn count_rules_with_tag(lines: &[&str], tag: &str) -> usize {
        lines.iter().filter(|line| line.contains(tag)).count()
    }

    async fn delete_interception_rules() -> Result<()> {
        for (family, table, chain) in [
            ("inet", "opensnitch", "filter_input"),
            ("inet", "opensnitch", "mangle_output"),
        ] {
            let listed = Self::delete_rules_matching_line(family, table, chain, |line| {
                line.contains("opensnitch-queue-dns")
                    || line.contains("opensnitch-queue-connections-non-tcp")
                    || line.contains("opensnitch-queue-connections-tcp-syn")
            })
            .await?;

            if !listed {
                tracing::warn!("error deleting interception rules from {family} {table} {chain}");
            }
        }

        Ok(())
    }

    async fn delete_rules_matching_line<F>(
        family: &str,
        table: &str,
        chain: &str,
        mut predicate: F,
    ) -> Result<bool>
    where
        F: FnMut(&str) -> bool,
    {
        let listing = match Self::list_chain(family, table, chain).await {
            Ok(listing) => listing,
            Err(_) => return Ok(false),
        };

        for line in listing.lines() {
            if !predicate(line) {
                continue;
            }

            let Some(handle) = FirewallNftAdapter::parse_nft_handle(line) else {
                continue;
            };

            Self::run_nft(&["delete", "rule", family, table, chain, "handle", &handle])
                .await
                .ok();
        }

        Ok(true)
    }

    async fn list_chain(family: &str, table: &str, chain: &str) -> Result<String> {
        let out = Command::new("nft")
            .args(["-a", "list", "chain", family, table, chain])
            .output()
            .await
            .with_context(|| format!("list nft chain {family} {table} {chain}"))?;

        if !out.status.success() {
            bail!(
                "error listing nftables chains ({}): {}",
                chain,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    async fn run_nft(args: &[&str]) -> Result<()> {
        let out = Command::new("nft")
            .args(args)
            .output()
            .await
            .with_context(|| format!("run nft with args: {}", args.join(" ")))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !stderr.is_empty() {
                tracing::warn!("nftables: error applying changes: {stderr}");
            }
            bail!("nft command failed: {}", String::from_utf8_lossy(&out.stderr));
        }

        Ok(())
    }

    async fn flush_conntrack() {
        let _ = flush_conntrack_table().await;
    }

    async fn ensure_system_chain(chain: &pb::FwChain) -> Result<()> {
        let family = FirewallNftAdapter::family_or_default(chain);
        let table = FirewallNftAdapter::table_or_default(chain);
        let name = FirewallNftAdapter::chain_name_or_default(chain);
        let hook = if chain.hook.is_empty() {
            "output"
        } else {
            chain.hook.as_str()
        };
        let policy = if chain.policy.is_empty() {
            "accept"
        } else {
            chain.policy.as_str()
        };
        let prio = if chain.priority.is_empty() {
            "0"
        } else {
            chain.priority.as_str()
        };
        let chain_types: &[&str] = match chain.r#type.as_str() {
            "mangle" if case_folded(hook) == "output" => &["route", "filter"],
            "mangle" => &["filter"],
            "natdest" | "natsource" | "nat" => &["nat"],
            "filter" => &["filter"],
            _ => &["filter"],
        };

        Self::run_nft(&["add", "table", family, table]).await.ok();

        Self::ensure_chain_with_fallback(family, table, name, hook, prio, policy, chain_types)
            .await?;

        Ok(())
    }

    async fn ensure_chain_with_fallback(
        family: &str,
        table: &str,
        chain: &str,
        hook: &str,
        prio: &str,
        policy: &str,
        chain_types: &[&str],
    ) -> Result<()> {
        if Self::chain_exists(family, table, chain).await {
            return Ok(());
        }

        for chain_type in chain_types {
            if Self::run_nft(&[
                "add", "chain", family, table, chain, "{", "type", chain_type, "hook", hook,
                "priority", prio, ";", "policy", policy, ";", "}",
            ])
            .await
            .is_ok()
            {
                return Ok(());
            }

            if Self::chain_exists(family, table, chain).await {
                return Ok(());
            }
        }

        bail!(
            "unable to ensure nft chain {family} {table} {chain} with chain types: {}",
            chain_types.join(",")
        )
    }

    async fn chain_exists(family: &str, table: &str, chain: &str) -> bool {
        Command::new("nft")
            .args(["list", "chain", family, table, chain])
            .output()
            .await
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    async fn chain_has_tag(chain: &pb::FwChain, tag: &str) -> Result<bool> {
        let listing = Self::list_chain(
            FirewallNftAdapter::family_or_default(chain),
            FirewallNftAdapter::table_or_default(chain),
            FirewallNftAdapter::chain_name_or_default(chain),
        )
        .await;
        Ok(listing.map(|s| s.contains(tag)).unwrap_or(false))
    }

    async fn delete_tagged_rules(chain: &pb::FwChain) -> Result<()> {
        let family = FirewallNftAdapter::family_or_default(chain);
        let table = FirewallNftAdapter::table_or_default(chain);
        let chain_name = FirewallNftAdapter::chain_name_or_default(chain);

        let _ = Self::delete_rules_matching_line(family, table, chain_name, |line| {
            line.contains(SYSFW_TAG_PREFIX)
        })
        .await?;

        Ok(())
    }
}

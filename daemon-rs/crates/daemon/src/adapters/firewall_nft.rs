use anyhow::{Context, Result, bail};
use opensnitch_proto::pb;
use tokio::process::Command;

use crate::utils::command_path::command_exists;

const SYSFW_TAG_PREFIX: &str = "opensnitch-sysfw:";

trait FwChainExt {
    fn family_or_default(&self) -> &str;
    fn table_or_default(&self) -> &str;
    fn chain_name_or_default(&self) -> &str;
    fn rule_tag(&self, rule: &pb::FwRule) -> String;
}

impl FwChainExt for pb::FwChain {
    fn family_or_default(&self) -> &str {
        if self.family.is_empty() {
            "inet"
        } else {
            self.family.as_str()
        }
    }

    fn table_or_default(&self) -> &str {
        if self.table.is_empty() {
            "opensnitch"
        } else {
            self.table.as_str()
        }
    }

    fn chain_name_or_default(&self) -> &str {
        if self.name.is_empty() {
            "mangle_output"
        } else {
            self.name.as_str()
        }
    }

    fn rule_tag(&self, rule: &pb::FwRule) -> String {
        let id = if !rule.uuid.is_empty() {
            rule.uuid.clone()
        } else {
            format!(
                "{}:{}:{}:{}",
                self.table_or_default(),
                self.chain_name_or_default(),
                rule.position,
                rule.description
            )
        };
        format!("{SYSFW_TAG_PREFIX}{id}")
    }
}

trait FwRuleNftExt {
    fn nft_expression(&self, queue_num: u16) -> String;
}

impl FwRuleNftExt for pb::FwRule {
    fn nft_expression(&self, queue_num: u16) -> String {
        if !self.parameters.is_empty() {
            let mut out = self.parameters.clone();
            if !self.target.is_empty() {
                out.push(' ');
                out.push_str(&self.target);
            }
            if !self.target_parameters.is_empty() {
                out.push(' ');
                out.push_str(&self.target_parameters);
            }
            return out;
        }

        let mut parts: Vec<String> = Vec::new();
        for expr in &self.expressions {
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

        if !self.target.is_empty() {
            parts.push(self.target.to_string());
        }

        if !self.target_parameters.is_empty() {
            let mut target_params = self.target_parameters.clone();
            if self.target.eq_ignore_ascii_case("queue")
                && target_params.contains("num 0")
                && queue_num != 0
            {
                target_params = target_params.replace("num 0", &format!("num {queue_num}"));
            }
            parts.push(target_params);
        }

        parts.join(" ")
    }
}

trait StrNftExt {
    fn nft_rule_lines(&self) -> Vec<&str>;
    fn parse_nft_handle(&self) -> Option<String>;
    fn nft_rule_tag(&self) -> &str;
}

impl StrNftExt for str {
    fn nft_rule_lines(&self) -> Vec<&str> {
        self.lines()
            .map(str::trim)
            .filter(|line| line.contains("# handle "))
            .collect()
    }

    fn parse_nft_handle(&self) -> Option<String> {
        self.split("# handle ")
            .nth(1)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    fn nft_rule_tag(&self) -> &str {
        if self.contains("opensnitch-queue-dns") {
            "opensnitch-queue-dns"
        } else if self.contains("opensnitch-queue-connections-non-tcp") {
            "opensnitch-queue-connections-non-tcp"
        } else if self.contains("opensnitch-queue-connections-tcp-syn") {
            "opensnitch-queue-connections-tcp-syn"
        } else {
            "opensnitch-queue-connections"
        }
    }
}

pub async fn ensure(queue_num: u16, queue_bypass: bool) -> Result<()> {
    if !command_exists("nft") {
        bail!("nft binary not found");
    }

    let queue_num = queue_num.to_string();
    let bypass = if queue_bypass { " bypass" } else { "" };

    run_nft(&["add", "table", "inet", "opensnitch"]).await.ok();
    run_nft(&[
        "add",
        "chain",
        "inet",
        "opensnitch",
        "filter_input",
        "{",
        "type",
        "filter",
        "hook",
        "input",
        "priority",
        "0",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])
    .await
    .ok();
    run_nft(&[
        "add",
        "chain",
        "inet",
        "opensnitch",
        "mangle_output",
        "{",
        "type",
        "route",
        "hook",
        "output",
        "priority",
        "0",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])
    .await
    .ok();

    if !interception_rules_valid().await? {
        delete_interception_rules().await.ok();
    }

    ensure_rule(
        "inet opensnitch filter_input",
        &format!(
            "udp sport 53 queue num {}{} comment \"opensnitch-queue-dns\"",
            queue_num, bypass
        ),
    )
    .await?;
    ensure_rule(
        "inet opensnitch mangle_output",
        &format!(
            "meta l4proto != tcp ct state new,related queue num {}{} comment \"opensnitch-queue-connections-non-tcp\"",
            queue_num, bypass
        ),
    )
    .await?;
    ensure_rule(
        "inet opensnitch mangle_output",
        &format!(
            "tcp flags & (fin|syn|rst|ack) == syn queue num {}{} comment \"opensnitch-queue-connections-tcp-syn\"",
            queue_num, bypass
        ),
    )
    .await?;

    flush_conntrack().await;

    Ok(())
}

pub async fn disable() -> Result<()> {
    if !command_exists("nft") {
        return Ok(());
    }

    let _ = run_nft(&["delete", "table", "inet", "opensnitch"]).await;
    Ok(())
}

pub async fn apply_system_firewall(sysfw: &pb::SysFirewall, queue_num: u16) -> Result<()> {
    if !sysfw.enabled {
        return Ok(());
    }

    for item in &sysfw.system_rules {
        for chain in &item.chains {
            ensure_system_chain(chain).await?;

            for rule in &chain.rules {
                if !rule.enabled {
                    continue;
                }

                let expr = rule.nft_expression(queue_num);
                if expr.is_empty() {
                    continue;
                }

                let tag = chain.rule_tag(rule);
                if chain_has_tag(chain, &tag).await? {
                    continue;
                }

                let mut args = vec!["add", "rule"];
                args.push(chain.family_or_default());
                args.push(chain.table_or_default());
                args.push(chain.chain_name_or_default());
                for token in expr.split_whitespace() {
                    args.push(token);
                }
                args.push("comment");
                let comment = format!("\"{tag}\"");
                args.push(comment.as_str());

                run_nft(&args).await?;
            }
        }
    }

    Ok(())
}

pub async fn clear_system_firewall(sysfw: &pb::SysFirewall) -> Result<()> {
    if !command_exists("nft") {
        return Ok(());
    }

    for item in &sysfw.system_rules {
        for chain in &item.chains {
            delete_tagged_rules(chain).await?;
        }
    }

    Ok(())
}

async fn ensure_rule(chain: &str, rule_expr: &str) -> Result<()> {
    let existing = Command::new("nft")
        .args(["-a", "list", "chain"])
        .args(chain.split_whitespace())
        .output()
        .await
        .context("list nft chain")?;

    if existing.status.success()
        && String::from_utf8_lossy(&existing.stdout).contains(rule_expr.nft_rule_tag())
    {
        return Ok(());
    }

    let mut args = vec!["add", "rule"];
    args.extend(chain.split_whitespace());
    args.extend(rule_expr.split_whitespace());

    run_nft(&args).await
}

async fn interception_rules_valid() -> Result<bool> {
    let input = list_chain("inet", "opensnitch", "filter_input").await?;
    let output = list_chain("inet", "opensnitch", "mangle_output").await?;

    let input_rules = input.nft_rule_lines();
    let output_rules = output.nft_rule_lines();

    let mut total_tagged = 0_usize;

    let dns_idx: Vec<usize> = input_rules
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| line.contains("opensnitch-queue-dns").then_some(idx))
        .collect();
    total_tagged += dns_idx.len();

    if dns_idx.len() != 1 || dns_idx[0] != 0 {
        return Ok(false);
    }

    let non_tcp_idx: Vec<usize> = output_rules
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            line.contains("opensnitch-queue-connections-non-tcp")
                .then_some(idx)
        })
        .collect();
    total_tagged += non_tcp_idx.len();

    let tcp_syn_idx: Vec<usize> = output_rules
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            line.contains("opensnitch-queue-connections-tcp-syn")
                .then_some(idx)
        })
        .collect();
    total_tagged += tcp_syn_idx.len();

    if non_tcp_idx.len() != 1 || tcp_syn_idx.len() != 1 {
        return Ok(false);
    }

    let output_len = output_rules.len();
    if output_len < 2 {
        return Ok(false);
    }

    let near_tail = |idx: usize| idx >= output_len.saturating_sub(2);
    if !near_tail(non_tcp_idx[0]) || !near_tail(tcp_syn_idx[0]) {
        return Ok(false);
    }

    Ok(total_tagged == 3)
}

async fn delete_interception_rules() -> Result<()> {
    for (family, table, chain) in [
        ("inet", "opensnitch", "filter_input"),
        ("inet", "opensnitch", "mangle_output"),
    ] {
        let listing = list_chain(family, table, chain).await?;
        for line in listing.lines() {
            if !(line.contains("opensnitch-queue-dns")
                || line.contains("opensnitch-queue-connections-non-tcp")
                || line.contains("opensnitch-queue-connections-tcp-syn"))
            {
                continue;
            }

            let Some(handle) = line.parse_nft_handle() else {
                continue;
            };

            run_nft(&["delete", "rule", family, table, chain, "handle", &handle])
                .await
                .ok();
        }
    }

    Ok(())
}

async fn list_chain(family: &str, table: &str, chain: &str) -> Result<String> {
    let out = Command::new("nft")
        .args(["-a", "list", "chain", family, table, chain])
        .output()
        .await
        .with_context(|| format!("list nft chain {family} {table} {chain}"))?;

    if !out.status.success() {
        return Ok(String::new());
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
        bail!(
            "nft command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    Ok(())
}

async fn flush_conntrack() {
    let _ = Command::new("conntrack").args(["-F"]).status().await;
}

async fn ensure_system_chain(chain: &pb::FwChain) -> Result<()> {
    let family = chain.family_or_default();
    let table = chain.table_or_default();
    let name = chain.chain_name_or_default();
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
    let chain_type = match chain.r#type.as_str() {
        "mangle" => "route",
        "natdest" | "natsource" | "nat" => "nat",
        "filter" => "filter",
        _ => "filter",
    };

    run_nft(&["add", "table", family, table]).await.ok();

    run_nft(&[
        "add", "chain", family, table, name, "{", "type", chain_type, "hook", hook, "priority",
        prio, ";", "policy", policy, ";", "}",
    ])
    .await
    .ok();

    Ok(())
}

async fn chain_has_tag(chain: &pb::FwChain, tag: &str) -> Result<bool> {
    let out = Command::new("nft")
        .args([
            "-a",
            "list",
            "chain",
            chain.family_or_default(),
            chain.table_or_default(),
            chain.chain_name_or_default(),
        ])
        .output()
        .await
        .context("list nft chain for system rule tag check")?;

    if !out.status.success() {
        return Ok(false);
    }

    Ok(String::from_utf8_lossy(&out.stdout).contains(tag))
}

async fn delete_tagged_rules(chain: &pb::FwChain) -> Result<()> {
    let family = chain.family_or_default();
    let table = chain.table_or_default();
    let chain_name = chain.chain_name_or_default();

    let out = Command::new("nft")
        .args(["-a", "list", "chain", family, table, chain_name])
        .output()
        .await
        .context("list nft chain for tagged system rule cleanup")?;

    if !out.status.success() {
        return Ok(());
    }

    let listing = String::from_utf8_lossy(&out.stdout);
    for line in listing.lines() {
        if !line.contains(SYSFW_TAG_PREFIX) {
            continue;
        }

        let handle = line.parse_nft_handle();

        let Some(handle) = handle else {
            continue;
        };

        run_nft(&[
            "delete", "rule", family, table, chain_name, "handle", &handle,
        ])
        .await
        .ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FwChainExt, FwRuleNftExt, StrNftExt};
    use opensnitch_proto::pb;

    #[test]
    fn chain_defaults_and_rule_tag_match_expected_values() {
        let chain = pb::FwChain::default();
        assert_eq!(chain.family_or_default(), "inet");
        assert_eq!(chain.table_or_default(), "opensnitch");
        assert_eq!(chain.chain_name_or_default(), "mangle_output");

        let fallback_tag = chain.rule_tag(&pb::FwRule {
            position: 7,
            description: "allow dns".to_string(),
            ..Default::default()
        });
        assert_eq!(
            fallback_tag,
            "opensnitch-sysfw:opensnitch:mangle_output:7:allow dns"
        );

        let uuid_tag = chain.rule_tag(&pb::FwRule {
            uuid: "uuid-1".to_string(),
            ..Default::default()
        });
        assert_eq!(uuid_tag, "opensnitch-sysfw:uuid-1");
    }

    #[test]
    fn nft_expression_prefers_parameters_and_appends_target_parts() {
        let rule = pb::FwRule {
            parameters: "tcp dport 443".to_string(),
            target: "accept".to_string(),
            target_parameters: "comment \"https\"".to_string(),
            ..Default::default()
        };

        assert_eq!(
            rule.nft_expression(0),
            "tcp dport 443 accept comment \"https\""
        );
    }

    #[test]
    fn nft_expression_builds_from_statements_and_rewrites_queue_num() {
        let rule = pb::FwRule {
            expressions: vec![pb::Expressions {
                statement: Some(pb::Statement {
                    op: "==".to_string(),
                    name: "meta".to_string(),
                    values: vec![pb::StatementValues {
                        key: "l4proto".to_string(),
                        value: "tcp".to_string(),
                    }],
                }),
            }],
            target: "queue".to_string(),
            target_parameters: "num 0 bypass".to_string(),
            ..Default::default()
        };

        assert_eq!(
            rule.nft_expression(42),
            "meta l4proto == tcp queue num 42 bypass"
        );
    }

    #[test]
    fn nft_rule_line_helpers_extract_handles_and_tags() {
        let listing = r#"
chain mangle_output {
    udp sport 53 queue num 0 comment "opensnitch-queue-dns" # handle 5
    tcp flags & (fin|syn|rst|ack) == syn queue num 0 comment "opensnitch-queue-connections-tcp-syn" # handle 7
}
"#;

        let lines = listing.nft_rule_lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].parse_nft_handle().as_deref(), Some("5"));
        assert_eq!(lines[1].parse_nft_handle().as_deref(), Some("7"));
        assert_eq!(lines[0].nft_rule_tag(), "opensnitch-queue-dns");
        assert_eq!(
            lines[1].nft_rule_tag(),
            "opensnitch-queue-connections-tcp-syn"
        );
    }
}

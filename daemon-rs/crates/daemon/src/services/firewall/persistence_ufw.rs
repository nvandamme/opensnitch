use anyhow::{Result, anyhow};

use crate::platform::firewall::config::{FirewallConfig, FirewallRule};
use crate::utils::command_path::resolve_command_path;

use super::firewall::FirewallService;
use super::persistence_authority::SYSFW_TAG_PREFIX;
use super::persistence_rule_parser::{collect_enabled_firewall_rules, parse_rule_parameters};

impl FirewallService {
    pub(super) fn persist_system_firewall_via_ufw(sysfw: &FirewallConfig) -> Result<()> {
        if resolve_command_path("ufw").is_none() {
            return Err(anyhow!(
                "ufw persistence selected but `ufw` is not available"
            ));
        }

        Self::clear_ufw_managed_rules()?;

        for rule in collect_enabled_firewall_rules(sysfw) {
            let tokens = Self::build_ufw_rule_tokens(rule)?;
            let mut args = vec!["--force"];
            args.extend(tokens.iter().map(String::as_str));
            if !Self::command_status_success("ufw", &args) {
                return Err(anyhow!(
                    "failed to apply ufw rule for chain `{}`",
                    rule.chain
                ));
            }
        }

        if !Self::command_status_success("ufw", &["reload"]) {
            return Err(anyhow!("failed to reload ufw after durable persistence"));
        }

        Ok(())
    }

    fn clear_ufw_managed_rules() -> Result<()> {
        let output = Self::command_stdout("ufw", &["status", "numbered"])
            .ok_or_else(|| anyhow!("failed to list ufw numbered rules for managed cleanup"))?;

        let mut ids = Vec::new();
        for line in output.lines() {
            if !line.contains(SYSFW_TAG_PREFIX) {
                continue;
            }
            let trimmed = line.trim();
            if !trimmed.starts_with('[') {
                continue;
            }
            let Some(end) = trimmed.find(']') else {
                continue;
            };
            let id = trimmed[1..end].trim();
            if let Ok(num) = id.parse::<u32>() {
                ids.push(num);
            }
        }

        ids.sort_unstable_by(|a, b| b.cmp(a));
        for id in ids {
            let id_s = id.to_string();
            let _ = Self::command_status_success("ufw", &["--force", "delete", id_s.as_str()]);
        }

        Ok(())
    }

    fn build_ufw_rule_tokens(rule: &FirewallRule) -> Result<Vec<String>> {
        let action = match rule.target.trim().to_ascii_lowercase().as_str() {
            "accept" | "allow" => "allow",
            "drop" | "deny" => "deny",
            "reject" => "reject",
            other => {
                return Err(anyhow!(
                    "ufw persistence does not support firewall target `{other}`"
                ));
            }
        };

        let parsed = parse_rule_parameters(rule);
        let chain = rule.chain.trim().to_ascii_uppercase();
        let mut out = Vec::new();

        if chain == "FORWARD" {
            out.push("route".to_string());
        }
        out.push(action.to_string());

        if matches!(chain.as_str(), "INPUT" | "FORWARD") {
            out.push("in".to_string());
            if let Some(iface) = parsed.in_interface.as_deref() {
                out.push("on".to_string());
                out.push(iface.to_string());
            }
        }
        if matches!(chain.as_str(), "OUTPUT" | "FORWARD") {
            out.push("out".to_string());
            if let Some(iface) = parsed.out_interface.as_deref() {
                out.push("on".to_string());
                out.push(iface.to_string());
            }
        }

        if let Some(proto) = parsed.proto.as_deref() {
            out.push("proto".to_string());
            out.push(proto.to_string());
        }

        out.push("from".to_string());
        out.push(parsed.src_ip.as_deref().unwrap_or("any").to_string());
        if let Some(src_port) = parsed.src_port.as_deref() {
            out.push("port".to_string());
            out.push(src_port.to_string());
        }

        out.push("to".to_string());
        out.push(parsed.dest_ip.as_deref().unwrap_or("any").to_string());
        if let Some(service_name) = parsed.service_name.as_deref() {
            if parsed.dest_ip.as_deref().unwrap_or("any") != "any" {
                return Err(anyhow!(
                    "ufw app-profile persistence requires destination `any` for profile `{service_name}`"
                ));
            }
            out.push("app".to_string());
            out.push(service_name.to_string());
        } else if let Some(dest_port) = parsed.dest_port.as_deref() {
            out.push("port".to_string());
            out.push(dest_port.to_string());
        }

        let id = if !rule.uuid.trim().is_empty() {
            rule.uuid.trim().to_string()
        } else if !rule.description.trim().is_empty() {
            rule.description.trim().replace(' ', "_")
        } else {
            "rule".to_string()
        };
        out.push("comment".to_string());
        out.push(format!("{SYSFW_TAG_PREFIX}{id}"));

        Ok(out)
    }
}

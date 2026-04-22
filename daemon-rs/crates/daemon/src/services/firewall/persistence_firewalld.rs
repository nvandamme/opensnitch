use std::collections::BTreeSet;
use std::fs;
use std::io::Write;

use anyhow::{Result, anyhow};

use crate::models::firewall_config::{FirewallConfig, FirewallRule};
use crate::utils::command_path::resolve_command_path;

use super::firewall::FirewallService;
use super::persistence_authority::{FIREWALLD_RICH_STATE_SUFFIX, SYSFW_TAG_PREFIX};
use super::persistence_rule_parser::{
    ParsedRuleParameters, build_direct_match_tokens, collect_enabled_firewall_rules_with_zone,
    parse_rule_parameters,
};

impl FirewallService {
    pub(super) fn persist_system_firewall_via_firewalld(
        state_anchor_path: &std::path::Path,
        sysfw: &FirewallConfig,
    ) -> Result<()> {
        if resolve_command_path("firewall-cmd").is_none() {
            return Err(anyhow!(
                "firewalld persistence selected but `firewall-cmd` is not available"
            ));
        }

        let state_path = Self::firewalld_rich_state_path(state_anchor_path);
        let previous_rich_rules = Self::load_firewalld_managed_rich_rules(&state_path);
        let mut desired_rich_rules = BTreeSet::new();
        for (rule, zone_name) in collect_enabled_firewall_rules_with_zone(sysfw) {
            let parsed = parse_rule_parameters(rule);
            if let Some(rich_rule) = Self::build_firewalld_rich_rule(rule, zone_name, &parsed)? {
                desired_rich_rules.insert((zone_name.unwrap_or("").to_string(), rich_rule));
            }
        }

        for (zone, rich_rule) in previous_rich_rules.difference(&desired_rich_rules) {
            let zone_arg = if zone.is_empty() {
                None
            } else {
                Some(format!("--zone={zone}"))
            };

            let mut runtime_remove = Vec::new();
            if let Some(zone_arg) = zone_arg.as_deref() {
                runtime_remove.push(zone_arg);
            }
            runtime_remove.push("--remove-rich-rule");
            runtime_remove.push(rich_rule.as_str());
            let _ = Self::command_status_success("firewall-cmd", &runtime_remove);

            let mut permanent_remove = Vec::new();
            permanent_remove.push("--permanent");
            if let Some(zone_arg) = zone_arg.as_deref() {
                permanent_remove.push(zone_arg);
            }
            permanent_remove.push("--remove-rich-rule");
            permanent_remove.push(rich_rule.as_str());
            let _ = Self::command_status_success("firewall-cmd", &permanent_remove);
        }

        Self::clear_firewalld_managed_rules(false)?;
        Self::clear_firewalld_managed_rules(true)?;
        Self::ensure_firewalld_zones_exist(sysfw)?;

        for (rule, zone_name) in collect_enabled_firewall_rules_with_zone(sysfw) {
            let parsed = parse_rule_parameters(rule);
            if let Some(rich_rule) = Self::build_firewalld_rich_rule(rule, zone_name, &parsed)? {
                let zone_arg = zone_name.map(|zone| format!("--zone={zone}"));
                let mut runtime_add = Vec::new();
                if let Some(zone_arg) = zone_arg.as_deref() {
                    runtime_add.push(zone_arg);
                }
                runtime_add.push("--add-rich-rule");
                runtime_add.push(rich_rule.as_str());
                if !Self::command_status_success("firewall-cmd", &runtime_add) {
                    let scope = zone_name.unwrap_or("default");
                    return Err(anyhow!(
                        "failed to apply firewalld runtime rich rule for zone `{scope}`"
                    ));
                }

                let mut permanent_add = Vec::new();
                permanent_add.push("--permanent");
                if let Some(zone_arg) = zone_arg.as_deref() {
                    permanent_add.push(zone_arg);
                }
                permanent_add.push("--add-rich-rule");
                permanent_add.push(rich_rule.as_str());
                if !Self::command_status_success("firewall-cmd", &permanent_add) {
                    let scope = zone_name.unwrap_or("default");
                    return Err(anyhow!(
                        "failed to apply firewalld permanent rich rule for zone `{scope}`"
                    ));
                }

                continue;
            }

            let family = Self::firewalld_family_for_rule(rule, &parsed);
            let table = if rule.table.trim().is_empty() {
                "filter".to_string()
            } else {
                rule.table.trim().to_ascii_lowercase()
            };
            let chain = if rule.chain.trim().is_empty() {
                "OUTPUT".to_string()
            } else {
                rule.chain.trim().to_string()
            };
            if zone_name.is_some() {
                return Err(anyhow!(
                    "firewalld zone persistence requires a rich-rule compatible firewall rule for chain `{chain}`"
                ));
            }
            let priority = rule.position.to_string();
            let args = Self::build_firewalld_rule_tokens(rule, &parsed);
            if args.is_empty() {
                continue;
            }

            let mut runtime_add = vec![
                "--direct",
                "--add-rule",
                family.as_str(),
                table.as_str(),
                chain.as_str(),
                priority.as_str(),
            ];
            runtime_add.extend(args.iter().map(String::as_str));
            if !Self::command_status_success("firewall-cmd", &runtime_add) {
                return Err(anyhow!(
                    "failed to apply firewalld runtime direct rule for chain `{chain}`"
                ));
            }

            let mut permanent_add = vec![
                "--permanent",
                "--direct",
                "--add-rule",
                family.as_str(),
                table.as_str(),
                chain.as_str(),
                priority.as_str(),
            ];
            permanent_add.extend(args.iter().map(String::as_str));
            if !Self::command_status_success("firewall-cmd", &permanent_add) {
                return Err(anyhow!(
                    "failed to apply firewalld permanent direct rule for chain `{chain}`"
                ));
            }
        }

        if !Self::command_status_success("firewall-cmd", &["--reload"]) {
            return Err(anyhow!(
                "failed to reload firewalld after durable persistence"
            ));
        }

        Self::save_firewalld_managed_rich_rules(&state_path, &desired_rich_rules)?;

        Ok(())
    }

    fn firewalld_rich_state_path(state_anchor_path: &std::path::Path) -> std::path::PathBuf {
        let mut name = state_anchor_path
            .file_name()
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_else(|| "firewall".to_string());
        name.push_str(FIREWALLD_RICH_STATE_SUFFIX);
        let base_dir = state_anchor_path
            .parent()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base_dir.join(name)
    }

    fn load_firewalld_managed_rich_rules(
        state_path: &std::path::Path,
    ) -> BTreeSet<(String, String)> {
        let raw = match fs::read_to_string(state_path) {
            Ok(raw) => raw,
            Err(_) => return BTreeSet::new(),
        };
        let mut out = BTreeSet::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, '\t');
            let zone = parts.next().unwrap_or_default().trim().to_string();
            let rule = parts.next().unwrap_or_default().trim().to_string();
            if !rule.is_empty() {
                out.insert((zone, rule));
            }
        }
        out
    }

    fn save_firewalld_managed_rich_rules(
        state_path: &std::path::Path,
        rules: &BTreeSet<(String, String)>,
    ) -> Result<()> {
        if rules.is_empty() {
            match fs::remove_file(state_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(anyhow!(
                        "failed to remove firewalld rich-rule state `{}`: {err}",
                        state_path.display()
                    ));
                }
            }
            return Ok(());
        }

        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                anyhow!(
                    "failed to create firewalld rich-rule state directory `{}`: {err}",
                    parent.display()
                )
            })?;
        }

        let mut file = fs::File::create(state_path).map_err(|err| {
            anyhow!(
                "failed to create firewalld rich-rule state `{}`: {err}",
                state_path.display()
            )
        })?;
        for (zone, rule) in rules {
            writeln!(file, "{zone}\t{rule}").map_err(|err| {
                anyhow!(
                    "failed to write firewalld rich-rule state `{}`: {err}",
                    state_path.display()
                )
            })?;
        }
        Ok(())
    }

    fn ensure_firewalld_zones_exist(sysfw: &FirewallConfig) -> Result<()> {
        if sysfw.zones.is_empty() {
            return Ok(());
        }

        let zones = Self::command_stdout("firewall-cmd", &["--get-zones"]).unwrap_or_default();
        let mut created = false;
        for zone in &sysfw.zones {
            let zone_name = zone.name.trim();
            if zone_name.is_empty() || zones.split_whitespace().any(|name| name == zone_name) {
                continue;
            }
            let new_zone_arg = format!("--new-zone={zone_name}");
            if !Self::command_status_success(
                "firewall-cmd",
                &["--permanent", new_zone_arg.as_str()],
            ) {
                return Err(anyhow!("failed to create firewalld zone `{zone_name}`"));
            }
            created = true;
        }

        if created && !Self::command_status_success("firewall-cmd", &["--reload"]) {
            return Err(anyhow!(
                "failed to reload firewalld after creating managed zones"
            ));
        }

        Ok(())
    }

    fn clear_firewalld_managed_rules(permanent: bool) -> Result<()> {
        let mut args = vec!["--direct", "--get-all-rules"];
        if permanent {
            args.insert(0, "--permanent");
        }

        let output = Self::command_stdout("firewall-cmd", &args).ok_or_else(|| {
            anyhow!("failed to list existing firewalld direct rules for managed cleanup")
        })?;

        for line in output.lines() {
            if !line.contains(SYSFW_TAG_PREFIX) {
                continue;
            }

            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 5 {
                continue;
            }

            let mut delete_args = vec![
                "--direct",
                "--remove-rule",
                tokens[0],
                tokens[1],
                tokens[2],
                tokens[3],
            ];
            delete_args.extend(tokens[4..].iter().copied());
            if permanent {
                delete_args.insert(0, "--permanent");
            }

            let _ = Self::command_status_success("firewall-cmd", &delete_args);
        }

        Ok(())
    }

    fn firewalld_family_for_rule(rule: &FirewallRule, parsed: &ParsedRuleParameters) -> String {
        if let Some(src) = parsed.src_ip.as_deref()
            && src.contains(':')
        {
            return "ipv6".to_string();
        }
        if let Some(dest) = parsed.dest_ip.as_deref()
            && dest.contains(':')
        {
            return "ipv6".to_string();
        }
        if rule.parameters.contains(':') {
            return "ipv6".to_string();
        }
        "ipv4".to_string()
    }

    fn build_firewalld_rule_tokens(
        rule: &FirewallRule,
        parsed: &ParsedRuleParameters,
    ) -> Vec<String> {
        let mut tokens = if rule.parameters.trim().is_empty() {
            build_direct_match_tokens(parsed)
        } else {
            rule.parameters
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };

        if !rule.target.trim().is_empty() {
            tokens.push("-j".to_string());
            tokens.push(rule.target.trim().to_string());
        }
        if !rule.target_parameters.trim().is_empty() {
            tokens.extend(
                rule.target_parameters
                    .split_whitespace()
                    .map(ToOwned::to_owned),
            );
        }

        let id = if !rule.uuid.trim().is_empty() {
            rule.uuid.trim().to_string()
        } else if !rule.description.trim().is_empty() {
            rule.description.trim().replace(' ', "_")
        } else {
            "rule".to_string()
        };
        tokens.push("-m".to_string());
        tokens.push("comment".to_string());
        tokens.push("--comment".to_string());
        tokens.push(format!("{SYSFW_TAG_PREFIX}{id}"));
        tokens
    }

    fn build_firewalld_rich_rule(
        rule: &FirewallRule,
        zone_name: Option<&str>,
        parsed: &ParsedRuleParameters,
    ) -> Result<Option<String>> {
        if zone_name.is_none() && parsed.service_name.is_none() {
            return Ok(None);
        }
        if parsed.in_interface.is_some() || parsed.out_interface.is_some() {
            return Ok(None);
        }

        let mut parts = vec!["rule".to_string()];
        let family = Self::firewalld_family_for_rule(rule, parsed);
        if parsed.src_ip.is_some() || parsed.dest_ip.is_some() {
            parts.push(format!("family=\"{family}\""));
        }
        if let Some(src_ip) = parsed.src_ip.as_deref() {
            parts.push(format!("source address=\"{src_ip}\""));
        }
        if let Some(dest_ip) = parsed.dest_ip.as_deref() {
            parts.push(format!("destination address=\"{dest_ip}\""));
        }

        if let Some(service_name) = parsed.service_name.as_deref() {
            parts.push(format!("service name=\"{service_name}\""));
        } else if let (Some(dest_port), Some(proto)) =
            (parsed.dest_port.as_deref(), parsed.proto.as_deref())
        {
            parts.push(format!("port port=\"{dest_port}\" protocol=\"{proto}\""));
        } else if let (Some(src_port), Some(proto)) =
            (parsed.src_port.as_deref(), parsed.proto.as_deref())
        {
            parts.push(format!(
                "source-port port=\"{src_port}\" protocol=\"{proto}\""
            ));
        } else if let Some(proto) = parsed.proto.as_deref() {
            parts.push(format!("protocol value=\"{proto}\""));
        }

        let action = match rule.target.trim().to_ascii_lowercase().as_str() {
            "accept" | "allow" => "accept",
            "drop" | "deny" => "drop",
            "reject" => "reject",
            other => {
                return Err(anyhow!(
                    "firewalld rich-rule persistence does not support firewall target `{other}`"
                ));
            }
        };
        parts.push(action.to_string());

        Ok(Some(parts.join(" ")))
    }
}

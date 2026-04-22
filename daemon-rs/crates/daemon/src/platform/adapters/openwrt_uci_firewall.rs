#![cfg(feature = "openwrt")]

use std::process::Command as StdCommand;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::{fs, io::Write};

use anyhow::{Context, Result};
use storage_format_core::StorageFormatCodec;
use storage_format_json::JsonStorageFormat;
use storage_format_uci::{UciCodecError, UciDocument, UciEntry, UciSection, UciStorageFormat};

use crate::models::firewall_config::{
    FirewallChain, FirewallConfig, FirewallExpression, FirewallRule, FirewallStatement,
    FirewallStatementValue, FirewallZone,
};
use crate::platform::ports::openwrt_uci_firewall_port::{
    FirewallPersistencePort, FirewallUciCommandRunnerPort,
};
use crate::utils::command_path::resolve_command_path;

const OPENWRT_FIREWALL_PACKAGE: &str = "firewall";
const OPENSNITCH_MANAGED_OPTION: &str = "opensnitch_managed";
const OPENSNITCH_SECTION_PREFIX: &str = "opensnitch_";
const OPENSNITCH_RULE_MAP_SUFFIX: &str = ".opensnitch.rule-map.json";

type RuleSectionMap = HashMap<String, String>;

/// OpenWrt firewall persistence adapter.
///
/// This adapter owns runtime command issuance for firewall persistence on
/// OpenWrt (`/etc/config/firewall` authority model). It intentionally keeps
/// persistence semantics outside storage codecs.
// Staged OpenWrt adapter API surface; production wiring lands in follow-up slices.
pub struct OpenWrtUciFirewallAdapter;

pub(crate) struct OpenWrtUciCommandRunner;

impl FirewallUciCommandRunnerPort for OpenWrtUciCommandRunner {
    fn run_uci_cli_command(&self, command: &str) -> Result<()> {
        if resolve_command_path("uci").is_none() {
            return Err(anyhow::anyhow!(
                "OpenWrt UCI CLI is not available in PATH; cannot persist firewall state"
            ));
        }

        let shell = resolve_command_path("sh").unwrap_or_else(|| "/bin/sh".to_string());
        let output = StdCommand::new(&shell)
            .args(["-c", command])
            .output()
            .with_context(|| {
                format!("spawn shell to execute OpenWrt UCI CLI command: {command}")
            })?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "OpenWrt UCI CLI command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        Ok(())
    }
}

impl OpenWrtUciFirewallAdapter {
    pub(crate) fn render_firewall_config_to_uci_text(sysfw: &FirewallConfig) -> String {
        UciStorageFormat.emit_document(&build_firewall_document(sysfw))
    }

    #[cfg(test)]
    pub(crate) fn build_firewall_config_cli_plan(sysfw: &FirewallConfig) -> Result<Vec<String>> {
        let raw = Self::render_firewall_config_to_uci_text(sysfw);
        <Self as FirewallPersistencePort>::build_firewall_persistence_plan(&raw)
    }

    #[cfg(test)]
    pub(crate) fn build_reconcile_cli_plan_for_test(
        existing_raw: &str,
        desired_raw: &str,
    ) -> Result<Vec<String>> {
        build_reconcile_uci_cli_plan(
            existing_raw,
            desired_raw,
            OPENWRT_FIREWALL_PACKAGE,
            &RuleSectionMap::new(),
        )
        .context("build OpenWrt firewall reconcile CLI plan for tests")
        .map(|(commands, _)| commands)
    }

    #[cfg(test)]
    pub(crate) fn build_reconcile_cli_plan_with_rule_map_for_test(
        existing_raw: &str,
        desired_raw: &str,
        rule_map: &RuleSectionMap,
    ) -> Result<Vec<String>> {
        build_reconcile_uci_cli_plan(
            existing_raw,
            desired_raw,
            OPENWRT_FIREWALL_PACKAGE,
            rule_map,
        )
        .context("build OpenWrt firewall reconcile CLI plan for tests with map")
        .map(|(commands, _)| commands)
    }

    pub(crate) fn persist_firewall_config_at_path(
        existing_path: Option<&Path>,
        sysfw: &FirewallConfig,
    ) -> Result<()> {
        let raw = Self::render_firewall_config_to_uci_text(sysfw);
        let runner = OpenWrtUciCommandRunner;
        let existing_raw = existing_path.and_then(|path| std::fs::read_to_string(path).ok());
        let map_path = existing_path.map(openwrt_rule_map_path);
        let existing_rule_map = map_path
            .as_deref()
            .map(load_openwrt_rule_map)
            .unwrap_or_default();
        let (commands, updated_rule_map) = if let Some(existing_raw) = existing_raw.as_deref() {
            build_reconcile_uci_cli_plan(
                existing_raw,
                &raw,
                OPENWRT_FIREWALL_PACKAGE,
                &existing_rule_map,
            )
            .context("build OpenWrt firewall reconcile CLI plan")?
        } else {
            (
                <Self as FirewallPersistencePort>::build_firewall_persistence_plan(&raw)?,
                build_rule_section_map_from_desired_uci(&raw),
            )
        };
        <Self as FirewallPersistencePort>::apply_cli_plan(&commands, &runner)?;

        apply_openwrt_firewall_runtime(&runner)?;

        if let Some(map_path) = map_path.as_deref() {
            save_openwrt_rule_map(map_path, &updated_rule_map)
                .context("persist OpenWrt rule section map")?;
        }

        Ok(())
    }

    pub(crate) fn load_firewall_from_uci_text(raw_uci_file_syntax: &str) -> Result<FirewallConfig> {
        let doc = UciStorageFormat.parse_document(raw_uci_file_syntax)?;
        Ok(parse_firewall_document(&doc))
    }

    pub(crate) fn load_firewall_from_uci_show_text(
        raw_uci_show_output: &str,
    ) -> Result<FirewallConfig> {
        let doc = parse_uci_show_document(raw_uci_show_output, OPENWRT_FIREWALL_PACKAGE)?;
        Ok(parse_firewall_document(&doc))
    }

    pub(crate) async fn extract_system_firewall_via_uci_show() -> Result<FirewallConfig> {
        if resolve_command_path("uci").is_none() {
            return Err(anyhow::anyhow!(
                "OpenWrt UCI CLI is not available in PATH; cannot introspect firewall state"
            ));
        }

        let output = tokio::process::Command::new("uci")
            .args(["show", OPENWRT_FIREWALL_PACKAGE])
            .output()
            .await
            .context("run `uci show firewall` for OpenWrt firewall introspection")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "OpenWrt UCI show command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        Self::load_firewall_from_uci_show_text(&raw)
    }
}

impl FirewallPersistencePort for OpenWrtUciFirewallAdapter {
    /// Build a deterministic `uci` command plan for the `firewall` package.
    fn build_firewall_persistence_plan(raw_uci_file_syntax: &str) -> Result<Vec<String>> {
        compile_uci_file_to_cli_plan(raw_uci_file_syntax, OPENWRT_FIREWALL_PACKAGE)
            .context("compile OpenWrt firewall UCI text into uci CLI persistence plan")
    }

    /// Execute a command plan through a runner abstraction.
    fn apply_cli_plan(
        commands: &[String],
        runner: &dyn FirewallUciCommandRunnerPort,
    ) -> Result<()> {
        for command in commands {
            runner
                .run_uci_cli_command(command)
                .with_context(|| format!("execute OpenWrt UCI CLI command: {command}"))?;
        }
        Ok(())
    }

    /// Compile and execute a persistence plan from UCI file-syntax input.
    fn persist_firewall_from_uci_text(
        raw_uci_file_syntax: &str,
        runner: &dyn FirewallUciCommandRunnerPort,
    ) -> Result<()> {
        let commands = Self::build_firewall_persistence_plan(raw_uci_file_syntax)?;
        Self::apply_cli_plan(&commands, runner)
    }
}

fn build_firewall_document(sysfw: &FirewallConfig) -> UciDocument {
    let mut sections = Vec::new();

    sections.push(UciSection {
        section_type: "system_fw".to_string(),
        name: Some(section_name("system_fw", "system_fw", 0)),
        entries: vec![
            UciEntry::Option {
                name: "enabled".to_string(),
                value: bool_to_uci(sysfw.enabled),
            },
            UciEntry::Option {
                name: "version".to_string(),
                value: sysfw.version.to_string(),
            },
        ],
    });

    for (index, zone) in sysfw.zones.iter().enumerate() {
        sections.push(build_zone_section(zone, index));
    }

    for chain in &sysfw.chains {
        sections.push(build_chain_section(chain, None));
    }
    for zone in &sysfw.zones {
        for chain in &zone.chains {
            sections.push(build_chain_section(chain, Some(zone.name.as_str())));
        }
    }

    for (index, rule) in sysfw.rules.iter().enumerate() {
        sections.push(build_rule_section(rule, None, index));
    }
    for chain in &sysfw.chains {
        for (index, rule) in chain.rules.iter().enumerate() {
            sections.push(build_rule_section(rule, None, index));
        }
    }
    for zone in &sysfw.zones {
        for chain in &zone.chains {
            for (index, rule) in chain.rules.iter().enumerate() {
                sections.push(build_rule_section(rule, Some(zone.name.as_str()), index));
            }
        }
    }

    UciDocument { sections }
}

fn build_zone_section(zone: &FirewallZone, index: usize) -> UciSection {
    UciSection {
        section_type: "zone".to_string(),
        name: Some(section_name(&zone.name, "opensnitch_zone", index)),
        entries: vec![UciEntry::Option {
            name: "name".to_string(),
            value: zone.name.clone(),
        }],
    }
}

fn build_chain_section(chain: &FirewallChain, zone_name: Option<&str>) -> UciSection {
    let mut entries = vec![
        UciEntry::Option {
            name: "table".to_string(),
            value: chain.table.clone(),
        },
        UciEntry::Option {
            name: "family".to_string(),
            value: chain.family.clone(),
        },
        UciEntry::Option {
            name: "priority".to_string(),
            value: chain.priority.clone(),
        },
        UciEntry::Option {
            name: "type".to_string(),
            value: chain.r#type.clone(),
        },
        UciEntry::Option {
            name: "hook".to_string(),
            value: chain.hook.clone(),
        },
        UciEntry::Option {
            name: "policy".to_string(),
            value: chain.policy.clone(),
        },
    ];

    if let Some(zone_name) = zone_name {
        entries.push(UciEntry::Option {
            name: "zone".to_string(),
            value: zone_name.to_string(),
        });
    }

    UciSection {
        section_type: "chain".to_string(),
        name: Some(section_name(&chain.name, "opensnitch_chain", 0)),
        entries,
    }
}

fn build_rule_section(rule: &FirewallRule, zone_name: Option<&str>, index: usize) -> UciSection {
    let mut entries = vec![
        UciEntry::Option {
            name: "name".to_string(),
            value: rule_name(rule, index),
        },
        UciEntry::Option {
            name: "table".to_string(),
            value: rule.table.clone(),
        },
        UciEntry::Option {
            name: "chain".to_string(),
            value: rule.chain.clone(),
        },
        UciEntry::Option {
            name: "enabled".to_string(),
            value: bool_to_uci(rule.enabled),
        },
        UciEntry::Option {
            name: "position".to_string(),
            value: rule.position.to_string(),
        },
        UciEntry::Option {
            name: "description".to_string(),
            value: rule.description.clone(),
        },
        UciEntry::Option {
            name: "parameters".to_string(),
            value: rule.parameters.clone(),
        },
        UciEntry::Option {
            name: "target".to_string(),
            value: rule.target.clone(),
        },
        UciEntry::Option {
            name: "target_parameters".to_string(),
            value: rule.target_parameters.clone(),
        },
    ];

    if let Some(zone_name) = zone_name {
        entries.push(UciEntry::Option {
            name: "zone".to_string(),
            value: zone_name.to_string(),
        });
    }

    for expression in render_rule_expression_statements(rule) {
        entries.push(UciEntry::List {
            name: "expression_statement".to_string(),
            value: expression,
        });
    }

    append_native_rule_fields(&mut entries, rule);

    UciSection {
        section_type: "rule".to_string(),
        name: Some(section_name(&rule.uuid, "opensnitch_rule", index)),
        entries,
    }
}

fn parse_firewall_document(doc: &UciDocument) -> FirewallConfig {
    let mut config = FirewallConfig::default();
    let mut top_level_chains = Vec::new();
    let mut zones: Vec<FirewallZone> = Vec::new();
    let mut deferred_rules: Vec<(FirewallRule, Option<String>)> = Vec::new();

    for section in &doc.sections {
        match section.section_type.as_str() {
            "system_fw" => {
                config.enabled = section_value(section, "enabled")
                    .map(|value| parse_uci_bool(&value))
                    .unwrap_or(false);
                config.version = section_value(section, "version")
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or_default();
            }
            "zone" => {
                let name = section_value(section, "name")
                    .or_else(|| section.name.clone())
                    .unwrap_or_default();
                if !name.is_empty() && zones.iter().all(|zone| zone.name != name) {
                    zones.push(FirewallZone {
                        name,
                        chains: Vec::new(),
                    });
                }
            }
            "chain" => {
                let zone_name = section_value(section, "zone");
                let chain = FirewallChain {
                    name: section
                        .name
                        .as_deref()
                        .map(normalize_managed_section_name)
                        .unwrap_or_default(),
                    table: section_value(section, "table").unwrap_or_default(),
                    family: section_value(section, "family").unwrap_or_default(),
                    priority: section_value(section, "priority").unwrap_or_default(),
                    r#type: section_value(section, "type").unwrap_or_default(),
                    hook: section_value(section, "hook").unwrap_or_default(),
                    policy: section_value(section, "policy").unwrap_or_default(),
                    rules: Vec::new(),
                };

                if let Some(zone_name) = zone_name.filter(|value| !value.is_empty()) {
                    upsert_zone(&mut zones, &zone_name).chains.push(chain);
                } else {
                    top_level_chains.push(chain);
                }
            }
            "rule" => {
                deferred_rules.push((parse_rule_section(section), section_value(section, "zone")));
            }
            _ => {}
        }
    }

    for (rule, zone_name) in deferred_rules {
        if let Some(chain) = find_chain_mut(
            &mut top_level_chains,
            &mut zones,
            &rule.chain,
            zone_name.as_deref(),
        ) {
            chain.rules.push(rule);
        } else {
            config.rules.push(rule);
        }
    }

    config.chains = top_level_chains;
    config.zones = zones;
    config
}

fn parse_rule_section(section: &UciSection) -> FirewallRule {
    let raw_expressions = section
        .entries
        .iter()
        .filter_map(|entry| match entry {
            UciEntry::List { name, value } if name == "expression_statement" => Some(value.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut parameters = section_value(section, "parameters").unwrap_or_default();
    if parameters.trim().is_empty() {
        parameters = native_fields_to_parameters(section);
    }

    FirewallRule {
        table: section_value(section, "table").unwrap_or_default(),
        chain: section_value(section, "chain").unwrap_or_default(),
        uuid: section
            .name
            .as_deref()
            .map(normalize_managed_section_name)
            .or_else(|| section_value(section, "name"))
            .unwrap_or_default(),
        enabled: section_value(section, "enabled")
            .map(|value| parse_uci_bool(&value))
            .unwrap_or(false),
        position: section_value(section, "position")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default(),
        description: section_value(section, "description")
            .or_else(|| section_value(section, "name"))
            .unwrap_or_default(),
        parameters,
        expressions: raw_expressions
            .into_iter()
            .map(|value| FirewallExpression {
                statement: Some(FirewallStatement {
                    op: "raw".to_string(),
                    name: "expression_statement".to_string(),
                    values: vec![FirewallStatementValue {
                        key: "raw".to_string(),
                        value,
                    }],
                }),
            })
            .collect(),
        target: section_value(section, "target").unwrap_or_default(),
        target_parameters: section_value(section, "target_parameters").unwrap_or_default(),
    }
}

fn find_chain_mut<'a>(
    chains: &'a mut [FirewallChain],
    zones: &'a mut [FirewallZone],
    chain_name: &str,
    zone_name: Option<&str>,
) -> Option<&'a mut FirewallChain> {
    if let Some(zone_name) = zone_name {
        if let Some(zone) = zones.iter_mut().find(|zone| zone.name == zone_name) {
            return zone
                .chains
                .iter_mut()
                .find(|chain| chain.name == chain_name);
        }
    }

    chains.iter_mut().find(|chain| chain.name == chain_name)
}

fn upsert_zone<'a>(zones: &'a mut Vec<FirewallZone>, name: &str) -> &'a mut FirewallZone {
    if let Some(index) = zones.iter().position(|zone| zone.name == name) {
        return &mut zones[index];
    }

    zones.push(FirewallZone {
        name: name.to_string(),
        chains: Vec::new(),
    });
    let index = zones.len() - 1;
    &mut zones[index]
}

fn section_option(section: &UciSection, name: &str) -> Option<String> {
    section.entries.iter().find_map(|entry| match entry {
        UciEntry::Option {
            name: entry_name,
            value,
        } if entry_name == name => Some(value.clone()),
        _ => None,
    })
}

fn section_values(section: &UciSection, name: &str) -> Vec<String> {
    section
        .entries
        .iter()
        .filter_map(|entry| match entry {
            UciEntry::List {
                name: entry_name,
                value,
            } if entry_name == name => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn section_value(section: &UciSection, name: &str) -> Option<String> {
    if let Some(value) = section_option(section, name) {
        return Some(value);
    }

    let values = section_values(section, name);
    if values.is_empty() {
        None
    } else {
        Some(values.join(" "))
    }
}

fn parse_uci_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn bool_to_uci(value: bool) -> String {
    if value {
        "1".to_string()
    } else {
        "0".to_string()
    }
}

fn rule_name(rule: &FirewallRule, index: usize) -> String {
    if !rule.description.trim().is_empty() {
        return rule.description.clone();
    }
    if !rule.uuid.trim().is_empty() {
        return rule.uuid.clone();
    }
    format!("OpenSnitch-Rule-{index}")
}

fn render_rule_expression_statements(rule: &FirewallRule) -> Vec<String> {
    let mut expressions = Vec::new();

    for expression in &rule.expressions {
        let Some(statement) = expression.statement.as_ref() else {
            continue;
        };

        if matches!(statement.op.as_str(), "raw")
            || matches!(
                statement.name.as_str(),
                "expression_statement" | "expression"
            )
        {
            for value in &statement.values {
                if !value.value.trim().is_empty() {
                    expressions.push(value.value.clone());
                }
            }
            continue;
        }

        let rendered = render_structured_statement(statement);
        if !rendered.is_empty() {
            expressions.push(rendered);
        }
    }

    expressions
}

fn render_structured_statement(statement: &FirewallStatement) -> String {
    let mut tokens = Vec::new();
    if !statement.name.trim().is_empty() {
        tokens.push(statement.name.trim().to_string());
    }
    for value in &statement.values {
        if !value.key.trim().is_empty() {
            tokens.push(value.key.trim().to_string());
        }
        if !statement.op.trim().is_empty() {
            tokens.push(statement.op.trim().to_string());
        }
        if !value.value.trim().is_empty() {
            tokens.push(value.value.trim().to_string());
        }
    }
    tokens.join(" ")
}

fn section_name(input: &str, fallback_prefix: &str, index: usize) -> String {
    let sanitized = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();

    let base = if sanitized.is_empty() {
        format!("{fallback_prefix}_{index}")
    } else {
        sanitized
    };

    if base.starts_with(OPENSNITCH_SECTION_PREFIX) {
        base
    } else {
        format!("{OPENSNITCH_SECTION_PREFIX}{base}")
    }
}

fn normalize_managed_section_name(name: &str) -> String {
    name.strip_prefix(OPENSNITCH_SECTION_PREFIX)
        .unwrap_or(name)
        .to_string()
}

fn parse_uci_show_document(raw: &str, package: &str) -> Result<UciDocument> {
    let mut sections = Vec::<(String, UciSection)>::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let lhs = lhs.trim();
        let rhs = rhs.trim();

        let prefix = format!("{package}.");
        if !lhs.starts_with(&prefix) {
            continue;
        }

        let suffix = &lhs[prefix.len()..];
        if let Some((section_ref, option_name)) = suffix.split_once('.') {
            let idx = upsert_show_section(&mut sections, section_ref, "rule");
            push_show_entry(&mut sections[idx].1, option_name.trim(), rhs);
            continue;
        }

        let section_ref = suffix.trim();
        let section_type = split_show_values(rhs)
            .into_iter()
            .next()
            .unwrap_or_else(|| default_type_fallback(section_ref));
        let idx = upsert_show_section(&mut sections, section_ref, &section_type);
        sections[idx].1.section_type = section_type;
    }

    Ok(UciDocument {
        sections: sections.into_iter().map(|(_, section)| section).collect(),
    })
}

fn upsert_show_section(
    sections: &mut Vec<(String, UciSection)>,
    section_ref: &str,
    default_type: &str,
) -> usize {
    if let Some(index) = sections.iter().position(|(key, _)| key == section_ref) {
        return index;
    }

    let (section_type, section_name) = parse_show_section_ref(section_ref, default_type);
    sections.push((
        section_ref.to_string(),
        UciSection {
            section_type,
            name: section_name,
            entries: Vec::new(),
        },
    ));
    sections.len() - 1
}

fn parse_show_section_ref(section_ref: &str, default_type: &str) -> (String, Option<String>) {
    let trimmed = section_ref.trim();
    if let Some(rest) = trimmed.strip_prefix('@')
        && let Some((section_type, _)) = rest.split_once('[')
    {
        return (section_type.to_string(), None);
    }

    (default_type.to_string(), Some(trimmed.to_string()))
}

fn default_type_fallback(section_ref: &str) -> String {
    parse_show_section_ref(section_ref, "rule").0
}

fn push_show_entry(section: &mut UciSection, option_name: &str, raw_value: &str) {
    let values = split_show_values(raw_value);
    if values.is_empty() {
        return;
    }

    if values.len() > 1 {
        // Multi-token show output like: option='a' 'b' maps to repeated list entries.
        for value in values {
            section.entries.push(UciEntry::List {
                name: option_name.to_string(),
                value,
            });
        }
        return;
    }

    let value = values[0].clone();

    if let Some(index) = section
        .entries
        .iter()
        .position(|entry| matches!(entry, UciEntry::Option { name, .. } if name == option_name))
    {
        if let UciEntry::Option { name, value: prior } = section.entries.remove(index) {
            section.entries.push(UciEntry::List {
                name: name.clone(),
                value: prior,
            });
            section.entries.push(UciEntry::List { name, value });
        }
        return;
    }

    if section
        .entries
        .iter()
        .any(|entry| matches!(entry, UciEntry::List { name, .. } if name == option_name))
    {
        section.entries.push(UciEntry::List {
            name: option_name.to_string(),
            value,
        });
        return;
    }

    section.entries.push(UciEntry::Option {
        name: option_name.to_string(),
        value,
    });
}

fn split_show_values(raw: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut i = 0;
    let bytes = raw.as_bytes();

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        if bytes[i] == b'\'' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'\'' {
                i += 1;
            }
            values.push(raw[start..i].to_string());
            if i < bytes.len() && bytes[i] == b'\'' {
                i += 1;
            }
            continue;
        }

        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        values.push(raw[start..i].to_string());
    }

    values
}

fn apply_openwrt_firewall_runtime(runner: &dyn FirewallUciCommandRunnerPort) -> Result<()> {
    if resolve_command_path("fw4").is_some() {
        return runner
            .run_uci_cli_command("fw4 reload")
            .context("reload firewall runtime through fw4");
    }

    if Path::new("/etc/init.d/firewall").exists() {
        return runner
            .run_uci_cli_command("/etc/init.d/firewall reload")
            .context("reload firewall runtime through init.d firewall script");
    }

    Err(anyhow::anyhow!(
        "OpenWrt firewall apply requested but no runtime reload command is available (expected fw4 or /etc/init.d/firewall)"
    ))
}

fn build_reconcile_uci_cli_plan(
    existing_raw: &str,
    desired_raw: &str,
    package: &str,
    existing_rule_map: &RuleSectionMap,
) -> Result<(Vec<String>, RuleSectionMap), UciCodecError> {
    let existing_doc = UciStorageFormat.parse_document(existing_raw)?;
    let desired_doc = UciStorageFormat.parse_document(desired_raw)?;
    Ok(build_reconcile_uci_cli_plan_from_docs(
        &existing_doc,
        &desired_doc,
        package,
        existing_rule_map,
    ))
}

fn build_reconcile_uci_cli_plan_from_docs(
    existing_doc: &UciDocument,
    desired_doc: &UciDocument,
    package: &str,
    existing_rule_map: &RuleSectionMap,
) -> (Vec<String>, RuleSectionMap) {
    let mut commands = Vec::new();
    let mut next_rule_map = RuleSectionMap::new();

    let existing_managed_by_key = existing_doc
        .sections
        .iter()
        .filter(|section| is_opensnitch_managed_section(section))
        .filter_map(|section| {
            let key = managed_section_identity_key(section)?;
            let name = section.name.clone()?;
            Some((key, (name, section)))
        })
        .collect::<HashMap<_, _>>();

    let existing_by_name = existing_doc
        .sections
        .iter()
        .filter_map(|section| section.name.as_ref().map(|name| (name.clone(), section)))
        .collect::<HashMap<_, _>>();

    let desired_keys = desired_doc
        .sections
        .iter()
        .filter_map(managed_section_identity_key)
        .collect::<HashSet<_>>();

    for (key, (name, _)) in &existing_managed_by_key {
        if desired_keys.contains(key) {
            continue;
        }
        commands.push(format!("uci delete {}.{}", package, name));
    }

    for desired in &desired_doc.sections {
        let Some(desired_key) = managed_section_identity_key(desired) else {
            commands.extend(build_section_uci_cli_commands(package, desired));
            continue;
        };

        let mut existing_match = existing_managed_by_key
            .get(&desired_key)
            .map(|(_, section)| *section);

        if existing_match.is_none()
            && desired.section_type == "rule"
            && let Some(rule_id) = managed_rule_id_from_section(desired)
            && let Some(mapped_name) = existing_rule_map.get(&rule_id)
            && let Some(mapped_section) = existing_by_name.get(mapped_name)
        {
            existing_match = Some(*mapped_section);
        }

        let merged = if let Some(existing) = existing_match {
            merge_desired_section_with_existing_unknown_fields(existing, desired)
        } else {
            desired.clone()
        };

        if let Some(existing) = existing_match
            && let Some(existing_name) = existing.name.as_deref()
        {
            if desired.section_type == "rule"
                && let Some(rule_id) = managed_rule_id_from_section(desired)
            {
                next_rule_map.insert(rule_id, existing_name.to_string());
            }
            commands.extend(build_named_section_uci_cli_commands_for_target(
                package,
                existing_name,
                &merged,
            ));
        } else {
            if desired.section_type == "rule"
                && let Some(rule_id) = managed_rule_id_from_section(desired)
                && let Some(desired_name) = desired.name.as_deref()
            {
                next_rule_map.insert(rule_id, desired_name.to_string());
            }
            commands.extend(build_named_section_uci_cli_commands(package, &merged));
        }
    }

    for (rule_id, section_name) in existing_rule_map {
        if next_rule_map.contains_key(rule_id) {
            continue;
        }
        if existing_by_name.contains_key(section_name) {
            commands.push(format!("uci delete {}.{}", package, section_name));
        }
    }

    commands.push(format!("uci commit {}", package));
    (commands, next_rule_map)
}

fn managed_section_identity_key(section: &UciSection) -> Option<String> {
    match section.section_type.as_str() {
        "system_fw" => Some("system_fw".to_string()),
        "zone" => section_value(section, "name").map(|name| format!("zone:{name}")),
        "chain" => Some(format!(
            "chain:{}|{}|{}|{}|{}|{}|{}",
            section_value(section, "table").unwrap_or_default(),
            section_value(section, "family").unwrap_or_default(),
            section_value(section, "priority").unwrap_or_default(),
            section_value(section, "type").unwrap_or_default(),
            section_value(section, "hook").unwrap_or_default(),
            section_value(section, "policy").unwrap_or_default(),
            section_value(section, "zone").unwrap_or_default(),
        )),
        "rule" => {
            if let Some(rule_id) = managed_rule_id_from_section(section) {
                return Some(format!("rule_id:{rule_id}"));
            }
            if let Some(name) = section_value(section, "name")
                && !name.trim().is_empty()
            {
                return Some(format!("rule_name:{name}"));
            }
            section
                .name
                .as_ref()
                .map(|name| format!("rule_section:{name}"))
        }
        _ => section.name.as_ref().map(|name| format!("section:{name}")),
    }
}

fn managed_rule_id_from_section(section: &UciSection) -> Option<String> {
    if section.section_type != "rule" {
        return None;
    }
    section
        .name
        .as_deref()
        .map(normalize_managed_section_name)
        .filter(|id| !id.trim().is_empty())
}

fn merge_desired_section_with_existing_unknown_fields(
    existing: &UciSection,
    desired: &UciSection,
) -> UciSection {
    let mut merged = desired.clone();
    let desired_keys = merged
        .entries
        .iter()
        .map(|entry| uci_entry_name(entry).to_string())
        .collect::<HashSet<_>>();

    for entry in &existing.entries {
        let key = uci_entry_name(entry);
        if is_opensnitch_owned_entry(existing.section_type.as_str(), key) {
            continue;
        }
        if desired_keys.contains(key) {
            continue;
        }
        merged.entries.push(entry.clone());
    }

    merged
}

fn build_named_section_uci_cli_commands(package: &str, section: &UciSection) -> Vec<String> {
    let Some(name) = section.name.as_deref() else {
        return Vec::new();
    };

    build_named_section_uci_cli_commands_for_target(package, name, section)
}

fn build_named_section_uci_cli_commands_for_target(
    package: &str,
    target_name: &str,
    section: &UciSection,
) -> Vec<String> {
    let mut commands = Vec::new();

    let target = format!("{}.{}", package, target_name);
    commands.push(format!(
        "uci set {}={}",
        target,
        shell_quote(&section.section_type)
    ));

    let list_keys = section
        .entries
        .iter()
        .filter_map(|entry| match entry {
            UciEntry::List { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<HashSet<_>>();

    for key in list_keys {
        commands.push(format!("uci delete {}.{}", target, key));
    }

    for entry in &section.entries {
        match entry {
            UciEntry::Option { name, value } => commands.push(format!(
                "uci set {}.{}={}",
                target,
                name,
                shell_quote(value)
            )),
            UciEntry::List { name, value } => commands.push(format!(
                "uci add_list {}.{}={}",
                target,
                name,
                shell_quote(value)
            )),
        }
    }

    commands
}

fn build_section_uci_cli_commands(package: &str, section: &UciSection) -> Vec<String> {
    let mut commands = Vec::new();
    let target = if let Some(name) = &section.name {
        commands.push(format!(
            "uci set {}.{}={}",
            package,
            name,
            shell_quote(&section.section_type)
        ));
        format!("{}.{}", package, name)
    } else {
        commands.push(format!("uci add {} {}", package, section.section_type));
        format!("{}.@{}[-1]", package, section.section_type)
    };

    for entry in &section.entries {
        match entry {
            UciEntry::Option { name, value } => commands.push(format!(
                "uci set {}.{}={}",
                target,
                name,
                shell_quote(value)
            )),
            UciEntry::List { name, value } => commands.push(format!(
                "uci add_list {}.{}={}",
                target,
                name,
                shell_quote(value)
            )),
        }
    }

    commands
}

fn uci_entry_name(entry: &UciEntry) -> &str {
    match entry {
        UciEntry::Option { name, .. } | UciEntry::List { name, .. } => name.as_str(),
    }
}

fn is_opensnitch_owned_entry(section_type: &str, entry_name: &str) -> bool {
    match section_type {
        "system_fw" => matches!(entry_name, "enabled" | "version"),
        "zone" => matches!(entry_name, "name"),
        "chain" => matches!(
            entry_name,
            "table" | "family" | "priority" | "type" | "hook" | "policy" | "zone"
        ),
        "rule" => matches!(
            entry_name,
            "name"
                | "table"
                | "chain"
                | "enabled"
                | "position"
                | "description"
                | "parameters"
                | "target"
                | "target_parameters"
                | "expression_statement"
                | "src"
                | "dest"
                | "proto"
                | "src_ip"
                | "dest_ip"
                | "src_port"
                | "dest_port"
        ),
        _ => false,
    }
}

fn is_opensnitch_managed_section(section: &UciSection) -> bool {
    if let Some(name) = section.name.as_deref()
        && name.starts_with(OPENSNITCH_SECTION_PREFIX)
    {
        return true;
    }

    // Backward compatibility with previously persisted marker-based sections.
    section_option(section, OPENSNITCH_MANAGED_OPTION)
        .map(|value| parse_uci_bool(&value))
        .unwrap_or(false)
}

fn openwrt_rule_map_path(firewall_path: &Path) -> std::path::PathBuf {
    let mut base = firewall_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "firewall".to_string());
    base.push_str(OPENSNITCH_RULE_MAP_SUFFIX);
    firewall_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(base)
}

fn load_openwrt_rule_map(path: &Path) -> RuleSectionMap {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return RuleSectionMap::new(),
    };
    crate::services::storage::StorageService::parse_with_storage_format_for_path(path, &raw)
        .unwrap_or_default()
}

fn save_openwrt_rule_map(path: &Path, map: &RuleSectionMap) -> Result<()> {
    if map.is_empty() {
        let _ = fs::remove_file(path);
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create OpenWrt rule map directory `{}`", parent.display()))?;
    }
    let mut file = fs::File::create(path)
        .with_context(|| format!("create OpenWrt rule map file `{}`", path.display()))?;
    let payload = JsonStorageFormat
        .convert_to_storage_pretty(map)
        .context("serialize OpenWrt rule section map")?;
    file.write_all(payload.as_bytes())
        .with_context(|| format!("write OpenWrt rule map file `{}`", path.display()))?;
    Ok(())
}

fn build_rule_section_map_from_desired_uci(raw: &str) -> RuleSectionMap {
    let Ok(doc) = UciStorageFormat.parse_document(raw) else {
        return RuleSectionMap::new();
    };
    let mut out = RuleSectionMap::new();
    for section in &doc.sections {
        if let Some(rule_id) = managed_rule_id_from_section(section)
            && let Some(name) = section.name.as_ref()
        {
            out.insert(rule_id, name.clone());
        }
    }
    out
}

fn append_native_rule_fields(entries: &mut Vec<UciEntry>, rule: &FirewallRule) {
    let parsed = parse_native_parameter_map(&rule.parameters);

    for key in [
        "src",
        "dest",
        "proto",
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
    ] {
        if let Some(value) = parsed.get(key)
            && !value.trim().is_empty()
        {
            upsert_option(entries, key, value.clone());
        }
    }
}

fn upsert_option(entries: &mut Vec<UciEntry>, name: &str, value: String) {
    if let Some(UciEntry::Option {
        value: entry_value, ..
    }) = entries.iter_mut().find(
        |entry| matches!(entry, UciEntry::Option { name: entry_name, .. } if entry_name == name),
    ) {
        *entry_value = value;
        return;
    }

    entries.push(UciEntry::Option {
        name: name.to_string(),
        value,
    });
}

fn parse_native_parameter_map(parameters: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let parts = parameters.split_whitespace().collect::<Vec<_>>();
    let mut idx = 0;

    while idx < parts.len() {
        match parts[idx] {
            "-p" | "--protocol" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("proto".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            "--dport" | "--destination-port" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("dest_port".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            "--sport" | "--source-port" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("src_port".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            "-s" | "--source" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("src_ip".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            "-d" | "--destination" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("dest_ip".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            "-i" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("src".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            "-o" => {
                if let Some(value) = parts.get(idx + 1) {
                    out.insert("dest".to_string(), (*value).to_string());
                    idx += 1;
                }
            }
            _ => {}
        }

        idx += 1;
    }

    out
}

fn native_fields_to_parameters(section: &UciSection) -> String {
    let mut tokens = Vec::new();

    if let Some(value) = section_value(section, "proto")
        && !value.trim().is_empty()
    {
        tokens.push("-p".to_string());
        tokens.push(value);
    }
    if let Some(value) = section_value(section, "src_ip")
        && !value.trim().is_empty()
    {
        tokens.push("-s".to_string());
        tokens.push(value);
    }
    if let Some(value) = section_value(section, "dest_ip")
        && !value.trim().is_empty()
    {
        tokens.push("-d".to_string());
        tokens.push(value);
    }
    if let Some(value) = section_value(section, "src")
        && !value.trim().is_empty()
    {
        tokens.push("-i".to_string());
        tokens.push(value);
    }
    if let Some(value) = section_value(section, "dest")
        && !value.trim().is_empty()
    {
        tokens.push("-o".to_string());
        tokens.push(value);
    }
    if let Some(value) = section_value(section, "src_port")
        && !value.trim().is_empty()
    {
        tokens.push("--sport".to_string());
        tokens.push(value);
    }
    if let Some(value) = section_value(section, "dest_port")
        && !value.trim().is_empty()
    {
        tokens.push("--dport".to_string());
        tokens.push(value);
    }

    tokens.join(" ")
}

// Planner helpers stay local to the adapter until production wiring lands.
fn build_uci_cli_plan(doc: &UciDocument, package: &str) -> Vec<String> {
    let mut commands = Vec::new();

    for section in &doc.sections {
        commands.extend(build_section_uci_cli_commands(package, section));
    }

    commands.push(format!("uci commit {}", package));
    commands
}
fn compile_uci_file_to_cli_plan(input: &str, package: &str) -> Result<Vec<String>, UciCodecError> {
    let doc = UciStorageFormat.parse_document(input)?;
    Ok(build_uci_cli_plan(&doc, package))
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

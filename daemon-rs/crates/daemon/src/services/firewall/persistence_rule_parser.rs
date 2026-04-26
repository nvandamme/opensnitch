use crate::models::firewall_config::{FirewallConfig, FirewallRule};

#[derive(Debug, Clone, Default)]
pub(super) struct ParsedRuleParameters {
    pub(super) proto: Option<String>,
    pub(super) src_ip: Option<String>,
    pub(super) dest_ip: Option<String>,
    pub(super) src_port: Option<String>,
    pub(super) dest_port: Option<String>,
    pub(super) in_interface: Option<String>,
    pub(super) out_interface: Option<String>,
    pub(super) service_name: Option<String>,
}

pub(super) fn collect_enabled_firewall_rules(sysfw: &FirewallConfig) -> Vec<&FirewallRule> {
    let mut out = Vec::new();

    for rule in &sysfw.rules {
        if rule.enabled {
            out.push(rule);
        }
    }

    for chain in &sysfw.chains {
        for rule in &chain.rules {
            if rule.enabled {
                out.push(rule);
            }
        }
    }

    for zone in &sysfw.zones {
        for chain in &zone.chains {
            for rule in &chain.rules {
                if rule.enabled {
                    out.push(rule);
                }
            }
        }
    }

    out
}

pub(super) fn collect_enabled_firewall_rules_with_zone(
    sysfw: &FirewallConfig,
) -> Vec<(&FirewallRule, Option<&str>)> {
    let mut out = Vec::new();

    for rule in &sysfw.rules {
        if rule.enabled {
            out.push((rule, None));
        }
    }

    for chain in &sysfw.chains {
        for rule in &chain.rules {
            if rule.enabled {
                out.push((rule, None));
            }
        }
    }

    for zone in &sysfw.zones {
        for chain in &zone.chains {
            for rule in &chain.rules {
                if rule.enabled {
                    out.push((rule, Some(zone.name.as_str())));
                }
            }
        }
    }

    out
}

pub(super) fn parse_rule_parameters(rule: &FirewallRule) -> ParsedRuleParameters {
    let mut parsed = ParsedRuleParameters::default();

    for expression in &rule.expressions {
        let Some(statement) = expression.statement.as_ref() else {
            continue;
        };
        let name = statement.name.trim().to_ascii_lowercase();
        if matches!(name.as_str(), "tcp" | "udp" | "sctp" | "dccp") {
            if parsed.proto.is_none() {
                parsed.proto = Some(name.clone());
            }
        }
        for value in &statement.values {
            let key = value.key.trim().to_ascii_lowercase();
            let data = value.value.trim();
            match key.as_str() {
                "dport" => {
                    parsed.dest_port.get_or_insert_with(|| data.to_string());
                }
                "sport" => {
                    parsed.src_port.get_or_insert_with(|| data.to_string());
                }
                "saddr" | "source" | "src" => {
                    parsed.src_ip.get_or_insert_with(|| data.to_string());
                }
                "daddr" | "destination" | "dst" => {
                    parsed.dest_ip.get_or_insert_with(|| data.to_string());
                }
                "iifname" | "in_interface" => {
                    parsed.in_interface.get_or_insert_with(|| data.to_string());
                }
                "oifname" | "out_interface" => {
                    parsed.out_interface.get_or_insert_with(|| data.to_string());
                }
                "l4proto" | "proto" | "protocol" => {
                    parsed
                        .proto
                        .get_or_insert_with(|| data.to_ascii_lowercase());
                }
                "service" | "app" | "profile" => {
                    parsed.service_name.get_or_insert_with(|| data.to_string());
                }
                _ => {}
            }
        }
        if matches!(name.as_str(), "service" | "app" | "profile") && parsed.service_name.is_none() {
            if let Some(value) = statement.values.first() {
                let data = value.value.trim();
                if !data.is_empty() {
                    parsed.service_name = Some(data.to_string());
                }
            }
        }
    }

    let tokens = rule.parameters.split_whitespace().collect::<Vec<_>>();
    let mut i = 0usize;
    while i < tokens.len() {
        match tokens[i] {
            "-p" | "--protocol" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed.proto.get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            "-s" | "--source" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed.src_ip.get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            "-d" | "--destination" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed.dest_ip.get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            "--sport" | "--source-port" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed.src_port.get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            "--dport" | "--destination-port" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed.dest_port.get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            "-i" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed
                        .in_interface
                        .get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            "-o" => {
                if let Some(value) = tokens.get(i + 1) {
                    parsed
                        .out_interface
                        .get_or_insert_with(|| (*value).to_string());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    parsed
}

pub(super) fn build_direct_match_tokens(parsed: &ParsedRuleParameters) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(proto) = parsed.proto.as_deref() {
        tokens.push("-p".to_string());
        tokens.push(proto.to_string());
    }
    if let Some(src_ip) = parsed.src_ip.as_deref() {
        tokens.push("-s".to_string());
        tokens.push(src_ip.to_string());
    }
    if let Some(dest_ip) = parsed.dest_ip.as_deref() {
        tokens.push("-d".to_string());
        tokens.push(dest_ip.to_string());
    }
    if let Some(in_interface) = parsed.in_interface.as_deref() {
        tokens.push("-i".to_string());
        tokens.push(in_interface.to_string());
    }
    if let Some(out_interface) = parsed.out_interface.as_deref() {
        tokens.push("-o".to_string());
        tokens.push(out_interface.to_string());
    }
    if let Some(src_port) = parsed.src_port.as_deref() {
        tokens.push("--sport".to_string());
        tokens.push(src_port.to_string());
    }
    if let Some(dest_port) = parsed.dest_port.as_deref() {
        tokens.push("--dport".to_string());
        tokens.push(dest_port.to_string());
    }
    tokens
}

use std::time::Duration;

use anyhow::Result;
use regex::Regex;

use crate::models::{rule_record::RuleOperator, rule_storage::RuleFileOperator};
use crate::utils::duration_parse::{DurationParseOptions, parse_human_duration};
use crate::utils::name_parsing::case_folded;

use super::RuleService;

impl RuleService {
    pub(super) fn operator_type_is(type_name: &str, expected: &str) -> bool {
        // Rule type tokens come from JSON/protobuf; use Unicode-aware comparison.
        case_folded(type_name) == case_folded(expected)
    }

    pub(super) fn operator_is_lists(type_name: &str, operand: &str) -> bool {
        Self::operator_type_is(type_name, "lists") || operand.starts_with("lists.")
    }

    pub(super) fn normalize_domain_list_entry(entry: &str) -> Option<String> {
        let line = entry.strip_suffix('\r').unwrap_or(entry).trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let host = if let Some(value) = line.strip_prefix("0.0.0.0") {
            value.trim()
        } else if let Some(value) = line.strip_prefix("127.0.0.1") {
            value.trim()
        } else {
            // Plain domain line; wildcard/glob handling is done by callers.
            line
        };

        if matches!(
            host,
            "local" | "localhost" | "localhost.localdomain" | "broadcasthost"
        ) {
            return None;
        }

        // DNS hostnames are case-insensitive (RFC 4343); normalise to lower-case
        // so set/trie lookups work regardless of capitalisation in the list file.
        Some(host.to_lowercase())
    }

    pub(super) fn wildcard_suffix(host: &str) -> Option<&str> {
        if let Some(value) = host.strip_prefix("*.") {
            let suffix = value.trim_matches('.');
            return (!suffix.is_empty()).then_some(suffix);
        }
        if let Some(value) = host.strip_prefix('.') {
            let suffix = value.trim_matches('.');
            return (!suffix.is_empty()).then_some(suffix);
        }
        None
    }

    pub(super) fn is_domain_glob_pattern(host: &str) -> bool {
        if RuleService::wildcard_suffix(host).is_some() {
            return false;
        }

        host.contains('?') || host.contains('[') || host.contains(']') || host.contains('*')
    }

    pub(super) fn compile_regex(pattern: &str, sensitive: bool) -> Option<Regex> {
        Regex::new(&RuleService::build_regex_pattern(pattern, sensitive)).ok()
    }

    pub(super) fn build_regex_pattern(pattern: &str, sensitive: bool) -> String {
        if sensitive {
            pattern.to_string()
        } else {
            pattern.to_lowercase()
        }
    }

    pub(super) fn parse_duration_spec(raw: &str) -> Option<Duration> {
        parse_human_duration(
            raw,
            DurationParseOptions {
                allow_fractional: true,
                min_ms: 1,
                min_s: 1,
                min_m: 1,
                min_h: 1,
            },
        )
    }

    pub(super) fn validate_operator(operator: &RuleOperator) -> Result<()> {
        if operator.type_name.trim().is_empty()
            && operator.operand.trim().is_empty()
            && operator.data.trim().is_empty()
            && operator.list.is_empty()
        {
            anyhow::bail!("invalid operator");
        }

        if !Self::operator_type_is(operator.type_name.as_str(), "simple")
            && !Self::operator_type_is(operator.type_name.as_str(), "regexp")
            && !Self::operator_type_is(operator.type_name.as_str(), "list")
            && operator.operand != "true"
            && operator.data.trim().is_empty()
        {
            anyhow::bail!(
                "operand {} cannot be empty for type {}",
                operator.operand,
                operator.type_name
            );
        }

        if Self::operator_type_is(operator.type_name.as_str(), "regexp")
            && RuleService::compile_regex(&operator.data, operator.sensitive).is_none()
        {
            anyhow::bail!("invalid regexp pattern: {}", operator.data);
        }

        if Self::operator_type_is(operator.type_name.as_str(), "simple")
            && operator.operand == "user.name"
        {
            let exists = nix::unistd::User::from_name(operator.data.as_str())
                .ok()
                .flatten()
                .is_some();
            if !exists {
                anyhow::bail!("invalid user.name operand: {}", operator.data);
            }
        }

        if Self::operator_type_is(operator.type_name.as_str(), "network")
            && operator.operand != "dest.network"
            && operator.operand != "source.network"
        {
            anyhow::bail!(
                "operand {} is only allowed with type network (dest.network or source.network)",
                operator.operand
            );
        }

        if Self::operator_type_is(operator.type_name.as_str(), "range") {
            let normalized = operator.data.replace(' ', "");
            let (min_raw, max_raw) = normalized
                .split_once('-')
                .ok_or_else(|| anyhow::anyhow!("invalid range format: {}", operator.data))?;
            let min = min_raw
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("invalid range minimum: {}", operator.data))?;
            let max = max_raw
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("invalid range maximum: {}", operator.data))?;
            if min > max {
                anyhow::bail!("range minimum is greater than maximum: {}", operator.data);
            }
        }

        if Self::operator_type_is(operator.type_name.as_str(), "lists") {
            match operator.operand.as_str() {
                "lists.domains"
                | "lists.domains_regexp"
                | "lists.ips"
                | "lists.nets"
                | "lists.hash.md5" => {}
                _ => anyhow::bail!("unknown lists operand: {}", operator.operand),
            }

            if let Some(scope) = operator.scope.as_deref().map(str::trim)
                && !scope.is_empty()
            {
                let lower = scope.to_lowercase();
                let valid_scope = lower == "src" || lower == "dst";
                if !valid_scope {
                    anyhow::bail!("invalid lists scope '{}': expected 'src' or 'dst'", scope);
                }

                let supports_scope =
                    operator.operand == "lists.ips" || operator.operand == "lists.nets";
                if !supports_scope {
                    anyhow::bail!(
                        "lists scope is only allowed for lists.ips or lists.nets (operand: {})",
                        operator.operand
                    );
                }
            }
        }

        if Self::operator_type_is(operator.type_name.as_str(), "list")
            && operator.list.is_empty()
            && !operator.data.trim().is_empty()
            && serde_json::from_str::<Vec<RuleFileOperator>>(&operator.data).is_err()
        {
            anyhow::bail!("invalid legacy list payload in operator data");
        }

        for sub in &operator.list {
            Self::validate_operator(sub)?;
        }

        Ok(())
    }
}

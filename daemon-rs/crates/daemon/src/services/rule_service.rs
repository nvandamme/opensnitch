use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use opensnitch_proto::pb;
use regex::Regex;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::models::{
    connection_state::ConnectionAttempt,
    process_state::ProcessInfo,
    rule_record::{RuleAction, RuleDuration, RuleOperator, RuleRecord},
    rule_storage::{RuleFile, RuleFileOperator},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMatchDecision {
    pub allow: bool,
    pub reject: bool,
}

impl RuleMatchDecision {
    fn from_action(action: RuleAction) -> Self {
        Self {
            allow: action.allows(),
            reject: action.rejects(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RegexCacheKey {
    pattern: String,
    sensitive: bool,
}

impl RegexCacheKey {
    fn new(pattern: &str, sensitive: bool) -> Self {
        Self {
            pattern: pattern.to_string(),
            sensitive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ListRegexCacheKey {
    path: PathBuf,
    sensitive: bool,
}

impl ListRegexCacheKey {
    fn new(path: &Path, sensitive: bool) -> Self {
        Self {
            path: path.to_path_buf(),
            sensitive,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RuleMatchCaches {
    list_entries: HashMap<PathBuf, Vec<String>>,
    list_regexes: HashMap<ListRegexCacheKey, Vec<Regex>>,
    network_aliases: HashMap<String, Vec<String>>,
    regexes: HashMap<RegexCacheKey, Regex>,
}

#[derive(Clone, Default)]
pub struct RuleService {
    rules: Arc<RwLock<Vec<RuleRecord>>>,
    rules_path: Arc<RwLock<PathBuf>>,
    match_caches: Arc<RwLock<RuleMatchCaches>>,
}

fn operator_matches_against(
    operator: &RuleOperator,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    dst_host: Option<&str>,
    caches: &RuleMatchCaches,
) -> bool {
    if operator.operand == "true" {
        return true;
    }

    if operator.operand == "list" || operator.type_name.eq_ignore_ascii_case("list") {
        return operator
            .list
            .iter()
            .all(|item| operator_matches_against(item, attempt, process, dst_host, caches));
    }

    if operator.operand == "process.parent.path" {
        return process
            .parent_chain
            .iter()
            .any(|parent| operator_matches_text(operator, parent.path.as_str(), caches));
    }

    if let Some(env_key) = operator.operand.strip_prefix("process.env.") {
        let env_value = process.env_preview_get(env_key).unwrap_or_default();
        return operator_matches_text(operator, &env_value, caches);
    }

    if operator.type_name.eq_ignore_ascii_case("lists") || operator.operand.starts_with("lists.") {
        return operator_matches_lists(operator, attempt, process, dst_host, caches);
    }

    if operator.type_name.eq_ignore_ascii_case("network") {
        return operator_matches_network(operator, attempt, caches);
    }

    if operator.type_name.eq_ignore_ascii_case("range") {
        let Some(candidate) = operator_operand_value(operator, attempt, process, dst_host) else {
            return false;
        };
        return candidate.matches_range_spec(&operator.data);
    }

    let Some(candidate) = operator_operand_value(operator, attempt, process, dst_host) else {
        return false;
    };

    operator_matches_text(operator, &candidate, caches)
}

fn operator_operand_value(
    operator: &RuleOperator,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    dst_host: Option<&str>,
) -> Option<String> {
    match operator.operand.as_str() {
        "process.path" => Some(process.path.clone()),
        "process.command" => Some(process.args.join(" ")),
        "process.parent.path" => process.parent_chain.first().map(|node| node.path.clone()),
        "process.id" => Some(process.pid.to_string()),
        "process.hash.sha1" => process.process_hash.clone(),
        "user.id" => Some(attempt.uid.to_string()),
        "dest.ip" => Some(attempt.dst_ip.clone()),
        "dest.network" => Some(attempt.dst_ip.clone()),
        "dest.host" => dst_host.map(ToOwned::to_owned),
        "dest.port" => Some(attempt.dst_port.to_string()),
        "source.ip" => Some(attempt.src_ip.clone()),
        "source.network" => Some(attempt.src_ip.clone()),
        "source.port" => Some(attempt.src_port.to_string()),
        "protocol" => Some(match attempt.protocol {
            crate::models::connection_state::TransportProtocol::Tcp => "tcp".to_string(),
            crate::models::connection_state::TransportProtocol::Udp => "udp".to_string(),
            crate::models::connection_state::TransportProtocol::UdpLite => "udplite".to_string(),
            crate::models::connection_state::TransportProtocol::Sctp => "sctp".to_string(),
            crate::models::connection_state::TransportProtocol::Icmp => "icmp".to_string(),
        }),
        _ => None,
    }
}

fn operator_matches_text(
    operator: &RuleOperator,
    candidate: &str,
    caches: &RuleMatchCaches,
) -> bool {
    if operator.type_name.eq_ignore_ascii_case("regexp") {
        return caches
            .regexes
            .get(&RegexCacheKey::new(&operator.data, operator.sensitive))
            .map(|regex| regex.is_match(candidate))
            .unwrap_or(false);
    }

    candidate.compare_with(&operator.data, operator.sensitive)
}

fn operator_matches_network(
    operator: &RuleOperator,
    attempt: &ConnectionAttempt,
    caches: &RuleMatchCaches,
) -> bool {
    let ip_text = match operator.operand.as_str() {
        "source.network" => attempt.src_ip.as_str(),
        _ => attempt.dst_ip.as_str(),
    };

    let ip = match ip_text.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    if let Some(alias_specs) = caches.network_aliases.get(operator.data.as_str()) {
        return alias_specs.iter().any(|spec| ip.matches_network_spec(spec));
    }

    ip.matches_network_spec(&operator.data)
}

fn operator_matches_lists(
    operator: &RuleOperator,
    attempt: &ConnectionAttempt,
    process: &ProcessInfo,
    dst_host: Option<&str>,
    caches: &RuleMatchCaches,
) -> bool {
    let operand = operator.operand.as_str();
    let list_path = PathBuf::from(operator.data.as_str());
    let entries = match caches.list_entries.get(&list_path) {
        Some(entries) => entries,
        None => return false,
    };

    match operand {
        "lists.domains" => {
            let Some(host) = dst_host.map(str::trim).filter(|value| !value.is_empty()) else {
                return false;
            };
            entries
                .iter()
                .map(|entry| normalize_domain_list_entry(entry))
                .any(|entry| host.compare_with(&entry, operator.sensitive))
        }
        "lists.domains_regexp" => {
            let Some(host) = dst_host.map(str::trim).filter(|value| !value.is_empty()) else {
                return false;
            };
            caches
                .list_regexes
                .get(&ListRegexCacheKey::new(&list_path, operator.sensitive))
                .map(|patterns| patterns.iter().any(|regex| regex.is_match(host)))
                .unwrap_or(false)
        }
        "lists.ips" => entries
            .iter()
            .any(|entry| attempt.dst_ip.compare_with(entry, operator.sensitive)),
        "lists.hash.md5" => {
            let Some(hash) = process.process_hash.as_deref() else {
                return true;
            };
            entries.iter().any(|entry| hash.compare_with(entry, true))
        }
        "lists.nets" => {
            let ip = match attempt.dst_ip.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => return false,
            };
            entries.iter().any(|entry| ip.matches_network_spec(entry))
        }
        _ => false,
    }
}

trait StrRangeExt {
    fn matches_range_spec(&self, range: &str) -> bool;
}

impl StrRangeExt for str {
    fn matches_range_spec(&self, range: &str) -> bool {
        let value = match self.trim().parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let (min_raw, max_raw) = match range.split_once('-') {
            Some(parts) => parts,
            None => return false,
        };
        let min = match min_raw.trim().parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let max = match max_raw.trim().parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        value >= min && value <= max
    }
}

trait ProcessInfoExt {
    fn env_preview_get(&self, key: &str) -> Option<String>;
}

impl ProcessInfoExt for ProcessInfo {
    fn env_preview_get(&self, key: &str) -> Option<String> {
        self.env_preview.iter().find_map(|item| {
            let (name, value) = item.split_once('=')?;
            if name == key {
                Some(value.to_string())
            } else {
                None
            }
        })
    }
}

trait StrCompareExt {
    fn compare_with(&self, expected: &str, sensitive: bool) -> bool;
}

impl StrCompareExt for str {
    fn compare_with(&self, expected: &str, sensitive: bool) -> bool {
        if sensitive {
            self == expected
        } else {
            self.eq_ignore_ascii_case(expected)
        }
    }
}

trait IpAddrNetworkExt {
    fn matches_network_spec(&self, spec: &str) -> bool;
    fn parse_network_spec(spec: &str) -> Option<(IpAddr, u8)>;
    fn prefix_match(&self, network: &IpAddr, prefix_len: u8) -> bool;
}

impl IpAddrNetworkExt for IpAddr {
    fn matches_network_spec(&self, spec: &str) -> bool {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return false;
        }

        let (network_ip, prefix_len) = match Self::parse_network_spec(trimmed) {
            Some(value) => value,
            None => return false,
        };

        self.prefix_match(&network_ip, prefix_len)
    }

    fn parse_network_spec(spec: &str) -> Option<(IpAddr, u8)> {
        if let Some((ip_raw, prefix_raw)) = spec.split_once('/') {
            let network_ip = ip_raw.trim().parse::<IpAddr>().ok()?;
            let prefix = prefix_raw.trim().parse::<u8>().ok()?;
            let max = match network_ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return None;
            }
            return Some((network_ip, prefix));
        }

        let ip = spec.parse::<IpAddr>().ok()?;
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((ip, prefix))
    }

    fn prefix_match(&self, network: &IpAddr, prefix_len: u8) -> bool {
        fn prefix_bytes_match(ip: &[u8], network: &[u8], prefix_len: u8) -> bool {
            if prefix_len == 0 {
                return true;
            }

            let full_bytes = usize::from(prefix_len / 8);
            let remaining_bits = prefix_len % 8;

            if ip[..full_bytes] != network[..full_bytes] {
                return false;
            }

            if remaining_bits == 0 {
                return true;
            }

            let mask = u8::MAX << (8 - remaining_bits);
            (ip[full_bytes] & mask) == (network[full_bytes] & mask)
        }

        match (self, network) {
            (IpAddr::V4(ip), IpAddr::V4(network)) => {
                let ip_octets = ip.octets();
                let network_octets = network.octets();
                prefix_bytes_match(&ip_octets, &network_octets, prefix_len)
            }
            (IpAddr::V6(ip), IpAddr::V6(network)) => {
                let ip_octets = ip.octets();
                let network_octets = network.octets();
                prefix_bytes_match(&ip_octets, &network_octets, prefix_len)
            }
            _ => false,
        }
    }
}

impl RuleService {
    pub async fn load_path<P>(&self, path: P) -> Result<usize>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_path_buf();
        let (loaded, temporary_rules) = load_rules_from_path(&path).await?;
        let caches = build_match_caches(&loaded).await?;

        *self.rules.write().await = loaded;
        *self.rules_path.write().await = path;
        *self.match_caches.write().await = caches;

        for (rule_name, duration) in temporary_rules {
            self.schedule_temporary_rule(rule_name, duration);
        }

        Ok(self.rules.read().await.len())
    }

    pub async fn reload(&self) -> Result<usize> {
        let path = self.rules_path.read().await.clone();
        self.load_path(path).await
    }

    pub async fn rules_path(&self) -> PathBuf {
        self.rules_path.read().await.clone()
    }

    pub async fn list_proto(&self) -> Vec<pb::Rule> {
        self.rules
            .read()
            .await
            .iter()
            .map(RuleRecord::to_proto)
            .collect()
    }

    pub async fn match_attempt(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<RuleMatchDecision>> {
        let rules = self.rules.read().await.clone();
        let caches = self.match_caches.read().await.clone();
        let mut decision = None;

        for rule in rules.iter().filter(|rule| rule.enabled) {
            if !operator_matches_against(&rule.operator, attempt, process, dst_host, &caches) {
                continue;
            }

            let matched = RuleMatchDecision::from_action(rule.action);
            if rule.precedence {
                return Ok(Some(matched));
            }
            decision = Some(matched);
        }

        Ok(decision)
    }

    pub async fn upsert_from_proto(&self, rule: &pb::Rule) -> Result<RuleMatchDecision> {
        let mut record = RuleRecord::from_proto(rule);
        let now = RuleRecord::now_timestamp();
        if record.created_at.is_none() {
            record.created_at = Some(now);
        }
        record.updated_at = Some(now);

        let decision = RuleMatchDecision::from_action(record.action);

        if record.duration == RuleDuration::Once {
            return Ok(decision);
        }

        self.upsert_record(record).await?;
        Ok(decision)
    }

    pub async fn delete_by_name(&self, rule_name: &str) -> Result<()> {
        let snapshot = {
            let mut rules = self.rules.write().await;
            rules.retain(|rule| rule.name != rule_name);
            rules.clone()
        };

        let path = self.rules_path.read().await.clone();
        let rule_name = rule_name.to_string();
        let file_path = path.join(format!("{rule_name}.json"));
        if let Err(err) = tokio::fs::remove_file(&file_path).await
            && err.kind() != ErrorKind::NotFound
        {
            return Err(err.into());
        }

        *self.match_caches.write().await = build_match_caches(&snapshot).await?;

        Ok(())
    }

    async fn upsert_record(&self, record: RuleRecord) -> Result<()> {
        let mut old_persisted = false;
        let snapshot = {
            let mut rules = self.rules.write().await;
            if let Some(existing) = rules.iter_mut().find(|current| current.name == record.name) {
                old_persisted = existing.duration.persists_to_disk();
                *existing = record.clone();
            } else {
                rules.push(record.clone());
                rules.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
            }
            rules.clone()
        };

        let path = self.rules_path.read().await.clone();
        let file_path = path.join(format!("{}.json", record.name));
        if old_persisted && !record.duration.persists_to_disk() {
            if let Err(err) = tokio::fs::remove_file(&file_path).await
                && err.kind() != ErrorKind::NotFound
            {
                return Err(err.into());
            }
        }

        if record.duration.persists_to_disk() {
            tokio::fs::create_dir_all(&path).await?;
            let raw = serde_json::to_string_pretty(&RuleFile::from(&record))?;
            tokio::fs::write(&file_path, raw).await?;
        }

        *self.match_caches.write().await = build_match_caches(&snapshot).await?;

        if record.enabled && record.duration.temporary_spec().is_some() {
            self.schedule_temporary_rule(record.name.clone(), record.duration.clone());
        }

        Ok(())
    }

    fn schedule_temporary_rule(&self, rule_name: String, duration: RuleDuration) {
        let Some(duration_spec) = duration.temporary_spec().map(ToOwned::to_owned) else {
            return;
        };
        let Some(timeout) = duration_spec.parse_duration_spec() else {
            warn!(rule = %rule_name, duration = %duration_spec, "invalid temporary rule duration; skipping expiry scheduling");
            return;
        };

        let service = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;

            let mut guard = service.rules.write().await;
            let Some(idx) = guard.iter().position(|item| item.name == rule_name) else {
                return;
            };

            let current = &guard[idx];
            if !current.enabled {
                return;
            }
            if current.duration.temporary_spec() != Some(duration_spec.as_str()) {
                return;
            }

            debug!(rule = %rule_name, duration = %duration_spec, "temporary rule expired");
            guard.remove(idx);
            let snapshot = guard.clone();
            drop(guard);

            match build_match_caches(&snapshot).await {
                Ok(caches) => {
                    *service.match_caches.write().await = caches;
                }
                Err(err) => {
                    warn!(rule = %rule_name, err = %err, "failed to refresh rule match caches after expiry");
                }
            }
        });
    }
}

async fn build_match_caches(rules: &[RuleRecord]) -> Result<RuleMatchCaches> {
    let mut list_paths = HashSet::new();
    let mut list_regex_paths = HashSet::new();
    let mut regex_keys = HashSet::new();
    let mut needs_network_aliases = false;

    for rule in rules.iter().filter(|rule| rule.enabled) {
        collect_operator_dependencies(
            &rule.operator,
            &mut list_paths,
            &mut list_regex_paths,
            &mut regex_keys,
            &mut needs_network_aliases,
        );
    }

    let mut caches = RuleMatchCaches::default();

    for path in list_paths {
        caches
            .list_entries
            .insert(path.clone(), load_list_entries_async(&path).await?);
    }

    for key in list_regex_paths {
        let entries = caches
            .list_entries
            .get(&key.path)
            .cloned()
            .unwrap_or_default();
        let regexes = entries
            .iter()
            .filter_map(|entry| compile_regex(entry, key.sensitive))
            .collect::<Vec<_>>();
        caches.list_regexes.insert(key, regexes);
    }

    for key in regex_keys {
        if let Some(regex) = compile_regex(&key.pattern, key.sensitive) {
            caches.regexes.insert(key, regex);
        }
    }

    if needs_network_aliases {
        caches.network_aliases = load_network_aliases_map().await;
    }

    Ok(caches)
}

fn collect_operator_dependencies(
    operator: &RuleOperator,
    list_paths: &mut HashSet<PathBuf>,
    list_regex_paths: &mut HashSet<ListRegexCacheKey>,
    regex_keys: &mut HashSet<RegexCacheKey>,
    needs_network_aliases: &mut bool,
) {
    if operator.type_name.eq_ignore_ascii_case("regexp") {
        regex_keys.insert(RegexCacheKey::new(&operator.data, operator.sensitive));
    }

    if operator.type_name.eq_ignore_ascii_case("lists") || operator.operand.starts_with("lists.") {
        let path = PathBuf::from(operator.data.as_str());
        list_paths.insert(path.clone());
        if operator.operand == "lists.domains_regexp" {
            list_regex_paths.insert(ListRegexCacheKey::new(&path, operator.sensitive));
        }
    }

    if operator.type_name.eq_ignore_ascii_case("network") {
        *needs_network_aliases = true;
    }

    for item in &operator.list {
        collect_operator_dependencies(
            item,
            list_paths,
            list_regex_paths,
            regex_keys,
            needs_network_aliases,
        );
    }
}

fn compile_regex(pattern: &str, sensitive: bool) -> Option<Regex> {
    Regex::new(&build_regex_pattern(pattern, sensitive)).ok()
}

fn build_regex_pattern(pattern: &str, sensitive: bool) -> String {
    if sensitive {
        pattern.to_string()
    } else {
        format!("(?i:{pattern})")
    }
}

fn normalize_domain_list_entry(entry: &str) -> String {
    if let Some(value) = entry.strip_prefix("0.0.0.0 ") {
        value.trim().to_string()
    } else if let Some(value) = entry.strip_prefix("127.0.0.1 ") {
        value.trim().to_string()
    } else {
        entry.to_string()
    }
}

async fn load_rules_from_path(
    path: &Path,
) -> Result<(Vec<RuleRecord>, Vec<(String, RuleDuration)>)> {
    let mut loaded = Vec::new();
    let mut temporary_rules = Vec::new();

    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok((loaded, temporary_rules)),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read rules directory {}", path.display()));
        }
    };

    while let Some(entry) = entries.next_entry().await? {
        let file_path = entry.path();
        if file_path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        let raw_rule = tokio::fs::read_to_string(&file_path)
            .await
            .with_context(|| format!("failed to read rule file {}", file_path.display()))?;
        let rule_file: RuleFile = serde_json::from_str(&raw_rule)
            .with_context(|| format!("failed to parse rule file {}", file_path.display()))?;
        let record = RuleRecord::from(rule_file);
        if record.enabled && record.duration.temporary_spec().is_some() {
            temporary_rules.push((record.name.clone(), record.duration.clone()));
        }
        loaded.push(record);
    }

    loaded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));

    Ok((loaded, temporary_rules))
}

trait StrDurationSpecExt {
    fn parse_duration_spec(&self) -> Option<Duration>;
}

impl StrDurationSpecExt for str {
    fn parse_duration_spec(&self) -> Option<Duration> {
        let value = self.trim().to_ascii_lowercase();
        let units = [
            ("ms", 1.0_f64),
            ("s", 1_000.0_f64),
            ("m", 60_000.0_f64),
            ("h", 3_600_000.0_f64),
        ];
        for (suffix, multiplier) in units {
            if let Some(number) = value.strip_suffix(suffix)
                && let Ok(parsed) = number.trim().parse::<f64>()
            {
                if parsed.is_sign_negative() || !parsed.is_finite() {
                    return None;
                }
                let millis = (parsed * multiplier).round() as u64;
                return Some(Duration::from_millis(millis.max(1)));
            }
        }
        None
    }
}

async fn load_list_entries_async(path: &Path) -> Result<Vec<String>> {
    let mut entries = Vec::new();

    let mut dir = match tokio::fs::read_dir(path).await {
        Ok(dir) => dir,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(entries),
        Err(err) => return Err(err.into()),
    };

    while let Some(entry) = dir.next_entry().await? {
        let file_path = entry.path();
        if !entry.file_type().await?.is_file() {
            continue;
        }

        let Some(name) = file_path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }

        let raw = tokio::fs::read_to_string(&file_path).await?;
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            entries.push(trimmed.to_string());
        }
    }

    Ok(entries)
}

async fn load_network_aliases_map() -> HashMap<String, Vec<String>> {
    let Some(path) = resolve_network_aliases_path() else {
        return HashMap::new();
    };

    let Ok(raw) = tokio::fs::read_to_string(path).await else {
        return HashMap::new();
    };

    serde_json::from_str::<HashMap<String, Vec<String>>>(&raw).unwrap_or_default()
}

fn resolve_network_aliases_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("OPENSNITCH_NETWORK_ALIASES_FILE").map(PathBuf::from)
        && path.exists()
    {
        return Some(path);
    }

    let system_path = PathBuf::from("/etc/opensnitchd/network_aliases.json");
    if system_path.exists() {
        return Some(system_path);
    }

    let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("daemon/data/network_aliases.json");
    dev_path.exists().then_some(dev_path)
}

impl From<RuleFile> for RuleRecord {
    fn from(rule: RuleFile) -> Self {
        Self {
            created_at: RuleRecord::parse_timestamp(&rule.created),
            updated_at: RuleRecord::parse_timestamp(&rule.updated),
            name: rule.name,
            description: rule.description,
            action: RuleAction::from_name(&rule.action),
            duration: RuleDuration::from_name(&rule.duration),
            enabled: rule.enabled,
            precedence: rule.precedence,
            nolog: rule.nolog,
            operator: RuleOperator::from(rule.operator),
        }
    }
}

impl From<&RuleRecord> for RuleFile {
    fn from(rule: &RuleRecord) -> Self {
        Self {
            created: rule
                .created_at
                .map(RuleRecord::format_timestamp)
                .unwrap_or_default(),
            updated: rule
                .updated_at
                .map(RuleRecord::format_timestamp)
                .unwrap_or_default(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            action: rule.action.as_str().to_string(),
            duration: rule.duration.as_str().to_string(),
            enabled: rule.enabled,
            precedence: rule.precedence,
            nolog: rule.nolog,
            operator: RuleFileOperator::from(&rule.operator),
        }
    }
}

impl From<RuleFileOperator> for RuleOperator {
    fn from(operator: RuleFileOperator) -> Self {
        Self {
            type_name: operator.r#type,
            operand: operator.operand,
            data: operator.data,
            sensitive: operator.sensitive,
            list: operator.list.into_iter().map(RuleOperator::from).collect(),
        }
    }
}

impl From<&RuleOperator> for RuleFileOperator {
    fn from(operator: &RuleOperator) -> Self {
        Self {
            r#type: operator.type_name.clone(),
            operand: operator.operand.clone(),
            data: operator.data.clone(),
            sensitive: operator.sensitive,
            list: operator.list.iter().map(RuleFileOperator::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use regex::Regex;
    use std::path::PathBuf;

    use crate::{
        models::{
            connection_state::{ConnectionAttempt, TransportProtocol},
            process_state::ProcessNode,
            rule_storage::{RuleFile, RuleFileOperator},
        },
        utils::test_support::TestDir,
    };

    use super::*;

    fn test_process() -> ProcessInfo {
        ProcessInfo {
            pid: 4242,
            path: "/usr/bin/curl".to_string(),
            args: vec!["curl".to_string()],
            cwd: None,
            env_preview: Vec::new(),
            process_hash: Some("hash-value".to_string()),
            parent_chain: vec![ProcessNode {
                pid: 1,
                path: "/sbin/init".to_string(),
            }],
        }
    }

    fn test_attempt(dst_ip: &str) -> ConnectionAttempt {
        ConnectionAttempt {
            request_id: 7,
            protocol: TransportProtocol::Tcp,
            src_ip: "127.0.0.1".to_string(),
            src_port: 12345,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            dns_query: None,
            pid: 4242,
            uid: 1000,
        }
    }

    async fn write_rule_file(
        rules_dir: &Path,
        name: &str,
        operator: RuleFileOperator,
    ) -> Result<()> {
        let rule = RuleFile {
            created: String::new(),
            updated: String::new(),
            name: name.to_string(),
            description: String::new(),
            action: "deny".to_string(),
            duration: "always".to_string(),
            enabled: true,
            precedence: false,
            nolog: false,
            operator,
        };

        tokio::fs::write(
            rules_dir.join(format!("{name}.json")),
            serde_json::to_string(&rule)?,
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn match_attempt_uses_cached_list_entries_after_source_removal() -> Result<()> {
        let rules_dir = TestDir::new("rule-service-rules");
        let list_dir = TestDir::new("rule-service-lists");
        tokio::fs::write(list_dir.path.join("domains.txt"), "example.org\n").await?;

        write_rule_file(
            &rules_dir.path,
            "cached-list",
            RuleFileOperator {
                r#type: "lists".to_string(),
                operand: "lists.domains".to_string(),
                data: list_dir.path.display().to_string(),
                sensitive: false,
                list: Vec::new(),
            },
        )
        .await?;

        let service = RuleService::default();
        service.load_path(&rules_dir.path).await?;

        tokio::fs::remove_dir_all(&list_dir.path).await?;

        let decision = service
            .match_attempt(
                &test_attempt("10.0.0.2"),
                &test_process(),
                Some("example.org"),
            )
            .await?;

        assert_eq!(
            decision,
            Some(RuleMatchDecision {
                allow: false,
                reject: false,
            })
        );

        Ok(())
    }

    #[tokio::test]
    async fn match_attempt_uses_cached_network_aliases_after_source_removal() -> Result<()> {
        let previous_aliases = std::env::var_os("OPENSNITCH_NETWORK_ALIASES_FILE");
        let rules_dir = TestDir::new("rule-service-rules");
        let alias_dir = TestDir::new("rule-service-aliases");
        let alias_file = alias_dir.path.join("network_aliases.json");
        tokio::fs::write(&alias_file, r#"{"corp":["10.10.0.0/16"]}"#).await?;
        unsafe {
            std::env::set_var("OPENSNITCH_NETWORK_ALIASES_FILE", &alias_file);
        }

        write_rule_file(
            &rules_dir.path,
            "cached-alias",
            RuleFileOperator {
                r#type: "network".to_string(),
                operand: "dest.network".to_string(),
                data: "corp".to_string(),
                sensitive: false,
                list: Vec::new(),
            },
        )
        .await?;

        let service = RuleService::default();
        service.load_path(&rules_dir.path).await?;

        tokio::fs::remove_file(&alias_file).await?;

        let decision = service
            .match_attempt(&test_attempt("10.10.4.7"), &test_process(), None)
            .await?;

        assert_eq!(
            decision,
            Some(RuleMatchDecision {
                allow: false,
                reject: false,
            })
        );

        if let Some(value) = previous_aliases {
            unsafe {
                std::env::set_var("OPENSNITCH_NETWORK_ALIASES_FILE", value);
            }
        } else {
            unsafe {
                std::env::remove_var("OPENSNITCH_NETWORK_ALIASES_FILE");
            }
        }

        Ok(())
    }

    #[test]
    fn regexp_operator_respects_sensitivity_setting() {
        let mut caches = RuleMatchCaches::default();
        let ins_key = RegexCacheKey::new("^example\\.org$", false);
        let sen_key = RegexCacheKey::new("^example\\.org$", true);
        caches
            .regexes
            .insert(ins_key.clone(), Regex::new(&build_regex_pattern(&ins_key.pattern, false)).expect("compile insensitive regex"));
        caches
            .regexes
            .insert(sen_key.clone(), Regex::new(&build_regex_pattern(&sen_key.pattern, true)).expect("compile sensitive regex"));

        let insensitive = RuleOperator {
            type_name: "regexp".to_string(),
            operand: "dest.host".to_string(),
            data: "^example\\.org$".to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let sensitive = RuleOperator {
            sensitive: true,
            ..insensitive.clone()
        };

        let attempt = test_attempt("10.0.0.3");
        let process = test_process();

        assert!(operator_matches_against(
            &insensitive,
            &attempt,
            &process,
            Some("ExAmPlE.OrG"),
            &caches
        ));
        assert!(!operator_matches_against(
            &sensitive,
            &attempt,
            &process,
            Some("ExAmPlE.OrG"),
            &caches
        ));
    }

    #[test]
    fn lists_domain_and_domain_regexp_match_expected_host_values() {
        let list_path = PathBuf::from("/tmp/test-domains");
        let mut caches = RuleMatchCaches::default();
        caches.list_entries.insert(
            list_path.clone(),
            vec![
                "0.0.0.0 example.org".to_string(),
                ".internal.example.org".to_string(),
            ],
        );
        caches.list_regexes.insert(
            ListRegexCacheKey::new(&list_path, false),
            vec![Regex::new("(?i:^api\\.example\\.org$)").expect("compile list regex")],
        );

        let domain_op = RuleOperator {
            type_name: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: list_path.display().to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let domain_re_op = RuleOperator {
            operand: "lists.domains_regexp".to_string(),
            ..domain_op.clone()
        };

        let attempt = test_attempt("10.0.0.4");
        let process = test_process();

        assert!(operator_matches_against(
            &domain_op,
            &attempt,
            &process,
            Some("example.org"),
            &caches
        ));
        assert!(operator_matches_against(
            &domain_re_op,
            &attempt,
            &process,
            Some("API.EXAMPLE.ORG"),
            &caches
        ));
        assert!(!operator_matches_against(
            &domain_re_op,
            &attempt,
            &process,
            Some("other.example.org"),
            &caches
        ));
    }

    #[test]
    fn range_operator_matches_within_bounds_only() {
        let range_op = RuleOperator {
            type_name: "range".to_string(),
            operand: "dest.port".to_string(),
            data: "100-200".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        let process = test_process();
        let mut in_attempt = test_attempt("10.0.0.5");
        in_attempt.dst_port = 150;
        let mut out_attempt = test_attempt("10.0.0.6");
        out_attempt.dst_port = 443;

        assert!(operator_matches_against(
            &range_op,
            &in_attempt,
            &process,
            None,
            &RuleMatchCaches::default()
        ));
        assert!(!operator_matches_against(
            &range_op,
            &out_attempt,
            &process,
            None,
            &RuleMatchCaches::default()
        ));
    }
}

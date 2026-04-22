use std::{
    collections::{HashMap, HashSet},
    ffi::CStr,
    io::ErrorKind,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use nix::libc;
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
    pub nolog: bool,
}

impl RuleMatchDecision {
    fn from_rule(action: RuleAction, nolog: bool) -> Self {
        Self {
            allow: action.allows(),
            reject: action.rejects(),
            nolog,
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

#[derive(Default)]
struct DomainWildcardTrieNode {
    children: HashMap<String, DomainWildcardTrieNode>,
    min_host_labels_required: Option<usize>,
}

#[derive(Default)]
struct DomainWildcardTrie {
    root: DomainWildcardTrieNode,
}

impl DomainWildcardTrie {
    fn insert_suffix(&mut self, suffix: &str) {
        let labels = suffix
            .split('.')
            .filter(|label| !label.is_empty())
            .collect::<Vec<_>>();
        if labels.is_empty() {
            return;
        }

        let mut node = &mut self.root;
        for label in labels.iter().rev() {
            node = node.children.entry((*label).to_string()).or_default();
        }

        let required = labels.len() + 1;
        node.min_host_labels_required = Some(
            node.min_host_labels_required
                .map(|current| current.min(required))
                .unwrap_or(required),
        );
    }

    fn matches_host(&self, host: &str) -> bool {
        let labels = host
            .split('.')
            .filter(|label| !label.is_empty())
            .collect::<Vec<_>>();
        if labels.is_empty() {
            return false;
        }

        let mut node = &self.root;
        for label in labels.iter().rev() {
            let Some(next) = node.children.get(*label) else {
                return false;
            };
            node = next;
            if let Some(min_required) = node.min_host_labels_required
                && labels.len() >= min_required
            {
                return true;
            }
        }

        false
    }
}

#[derive(Default)]
struct CidrTrieNode {
    terminal: bool,
    zero: Option<Box<CidrTrieNode>>,
    one: Option<Box<CidrTrieNode>>,
}

#[derive(Default)]
struct CidrTrieIndex {
    has_entries: bool,
    v4: CidrTrieNode,
    v6: CidrTrieNode,
}

impl CidrTrieIndex {
    fn insert(&mut self, network: IpAddr, prefix_len: u8) {
        self.has_entries = true;
        match network {
            IpAddr::V4(ip) => Self::insert_bits(&mut self.v4, &ip.octets(), prefix_len),
            IpAddr::V6(ip) => Self::insert_bits(&mut self.v6, &ip.octets(), prefix_len),
        }
    }

    fn has_entries(&self) -> bool {
        self.has_entries
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => Self::contains_bits(&self.v4, &ip.octets(), 32),
            IpAddr::V6(ip) => Self::contains_bits(&self.v6, &ip.octets(), 128),
        }
    }

    fn insert_bits(root: &mut CidrTrieNode, octets: &[u8], prefix_len: u8) {
        let mut node = root;
        for bit_idx in 0..usize::from(prefix_len) {
            let byte = octets[bit_idx / 8];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;
            let next = if bit == 0 {
                &mut node.zero
            } else {
                &mut node.one
            };
            node = next.get_or_insert_with(|| Box::new(CidrTrieNode::default()));
        }
        node.terminal = true;
    }

    fn contains_bits(root: &CidrTrieNode, octets: &[u8], max_bits: u8) -> bool {
        let mut node = root;
        if node.terminal {
            return true;
        }

        for bit_idx in 0..usize::from(max_bits) {
            let byte = octets[bit_idx / 8];
            let bit = (byte >> (7 - (bit_idx % 8))) & 1;
            let next = if bit == 0 {
                node.zero.as_deref()
            } else {
                node.one.as_deref()
            };
            let Some(next_node) = next else {
                return false;
            };
            node = next_node;
            if node.terminal {
                return true;
            }
        }

        false
    }
}

struct ListRegexCache {
    aho_regexes: Vec<Regex>,
    fallback_regexes: Vec<Regex>,
    aho: Option<AhoCorasick>,
    aho_pattern_to_regex_indices: Vec<Vec<usize>>,
}

const AHO_MIN_REGEXES: usize = 128;
const AHO_MIN_LITERAL_COVERAGE: f64 = 0.6;
const AHO_MIN_AVG_LITERAL_LEN: f64 = 6.0;

#[derive(Default)]
struct RuleMatchCaches {
    list_domains: HashMap<PathBuf, HashSet<String>>,
    list_domain_wildcards: HashMap<PathBuf, DomainWildcardTrie>,
    list_domain_globs: HashMap<PathBuf, Vec<GlobMatcher>>,
    list_trimmed_values: HashMap<PathBuf, HashSet<String>>,
    list_networks: HashMap<PathBuf, CidrTrieIndex>,
    list_regexes: HashMap<ListRegexCacheKey, ListRegexCache>,
    network_aliases: HashMap<String, Vec<String>>,
    regexes: HashMap<RegexCacheKey, Regex>,
}

#[derive(Debug, Clone, Default)]
struct ListPathNeeds {
    domains: bool,
    trimmed_values: bool,
    networks: bool,
    regex_sensitivities: HashSet<bool>,
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

    if operator.type_name.eq_ignore_ascii_case("simple")
        && matches!(
            operator.operand.as_str(),
            "process.hash.md5" | "process.hash.sha1"
        )
    {
        let Some(hash) = operator_operand_value(operator, attempt, process, dst_host) else {
            // Go hash operators return true when checksum data is unavailable.
            return true;
        };
        return operator_matches_text(operator, &hash, caches);
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

    if operator.operand == "user.name" {
        let Some(uid) = nix::unistd::User::from_name(operator.data.as_str())
            .ok()
            .flatten()
            .map(|user| user.uid.as_raw().to_string())
        else {
            return false;
        };
        return attempt.uid.to_string().compare_with(&uid, true);
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
        "process.hash.sha1" => process.process_hash_sha1.clone(),
        "process.hash.md5" => process.process_hash_md5.clone(),
        "user.id" => Some(attempt.uid.to_string()),
        "dest.ip" => Some(attempt.dst_ip.clone()),
        "dest.network" => Some(attempt.dst_ip.clone()),
        "dest.host" => dst_host.map(ToOwned::to_owned),
        "dest.port" => Some(attempt.dst_port.to_string()),
        "source.ip" => Some(attempt.src_ip.clone()),
        "source.network" => Some(attempt.src_ip.clone()),
        "source.port" => Some(attempt.src_port.to_string()),
        "iface.in" => interface_name_by_index(attempt.iface_in_idx),
        "iface.out" => interface_name_by_index(attempt.iface_out_idx),
        "protocol" => Some(match attempt.protocol {
            crate::models::connection_state::TransportProtocol::Tcp => "TCP".to_string(),
            crate::models::connection_state::TransportProtocol::Udp => "UDP".to_string(),
            crate::models::connection_state::TransportProtocol::UdpLite => "UDPLITE".to_string(),
            crate::models::connection_state::TransportProtocol::Sctp => "SCTP".to_string(),
            crate::models::connection_state::TransportProtocol::Icmp => "ICMP".to_string(),
        }),
        _ => None,
    }
}

fn interface_name_by_index(index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }

    let mut name = [0_i8; libc::IF_NAMESIZE];
    // SAFETY: if_indextoname writes a NUL-terminated interface name into the provided fixed-size buffer.
    let ptr = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }

    // SAFETY: libc guarantees returned pointer references a NUL-terminated string in `name`.
    Some(
        unsafe { CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn operator_matches_text(
    operator: &RuleOperator,
    candidate: &str,
    caches: &RuleMatchCaches,
) -> bool {
    if operator.type_name.eq_ignore_ascii_case("regexp") {
        let lowered;
        let value = if operator.sensitive {
            candidate
        } else {
            lowered = candidate.to_lowercase();
            lowered.as_str()
        };

        return caches
            .regexes
            .get(&RegexCacheKey::new(&operator.data, operator.sensitive))
            .map(|regex| regex.is_match(value))
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

    match operand {
        "lists.domains" => {
            let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty()) else {
                return false;
            };

            // Go lists.domains lowers only the candidate host when sensitive=false,
            // then performs exact map-key lookup against loaded entries.
            let lowered;
            if !operator.sensitive {
                lowered = host.to_ascii_lowercase();
                host = lowered.as_str();
            }

            if caches
                .list_domains
                .get(&list_path)
                .map(|set| set.contains(host))
                .unwrap_or(false)
            {
                return true;
            }

            if caches
                .list_domain_wildcards
                .get(&list_path)
                .map(|trie| trie.matches_host(host))
                .unwrap_or(false)
            {
                return true;
            }

            caches
                .list_domain_globs
                .get(&list_path)
                .map(|globs| globs.iter().any(|glob| glob.is_match(host)))
                .unwrap_or(false)
        }
        "lists.domains_regexp" => {
            let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty()) else {
                return false;
            };

            // Go lists.domains_regexp lowers only the candidate host when
            // sensitive=false and uses regexes compiled from raw list lines.
            let lowered;
            if !operator.sensitive {
                lowered = host.to_ascii_lowercase();
                host = lowered.as_str();
            }

            caches
                .list_regexes
                .get(&ListRegexCacheKey::new(&list_path, operator.sensitive))
                .map(|cache| cache.matches(host))
                .unwrap_or(false)
        }
        "lists.ips" => {
            caches
                .list_trimmed_values
                .get(&list_path)
                .map(|set| {
                    if operator.sensitive {
                        set.contains(attempt.dst_ip.as_str())
                    } else {
                        let lowered = attempt.dst_ip.to_ascii_lowercase();
                        set.contains(lowered.as_str())
                    }
                })
                .unwrap_or(false)
                || attempt
                    .dst_ip
                    .parse::<IpAddr>()
                    .ok()
                    .and_then(|ip| {
                        caches
                            .list_networks
                            .get(&list_path)
                            .filter(|index| index.has_entries())
                            .map(|index| index.contains(ip))
                    })
                    .unwrap_or(false)
        }
        "lists.hash.md5" => {
            let Some(hash) = process.process_hash_md5.as_deref() else {
                return false;
            };
            caches
                .list_trimmed_values
                .get(&list_path)
                .map(|set| set.contains(hash.trim()))
                .unwrap_or(false)
        }
        "lists.nets" => {
            if caches
                .list_trimmed_values
                .get(&list_path)
                .map(|set| {
                    if operator.sensitive {
                        set.contains(attempt.dst_ip.as_str())
                    } else {
                        let lowered = attempt.dst_ip.to_ascii_lowercase();
                        set.contains(lowered.as_str())
                    }
                })
                .unwrap_or(false)
            {
                return true;
            }

            attempt
                .dst_ip
                .parse::<IpAddr>()
                .ok()
                .and_then(|ip| {
                    caches
                        .list_networks
                        .get(&list_path)
                        .filter(|index| index.has_entries())
                        .map(|index| index.contains(ip))
                })
                .unwrap_or(false)
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

    #[cfg(test)]
    pub async fn match_attempt(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<RuleMatchDecision>> {
        Ok(self
            .match_attempt_with_rule_name(attempt, process, dst_host)
            .await?
            .map(|(decision, _)| decision))
    }

    pub async fn match_attempt_with_rule_name(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<(RuleMatchDecision, String)>> {
        let rules = self.rules.read().await;
        let caches = self.match_caches.read().await;
        let mut decision = None;

        for rule in rules.iter().filter(|rule| rule.enabled) {
            if !operator_matches_against(&rule.operator, attempt, process, dst_host, &caches) {
                continue;
            }

            let matched = RuleMatchDecision::from_rule(rule.action, rule.nolog);
            if rule.precedence || !matched.allow {
                return Ok(Some((matched, rule.name.clone())));
            }
            decision = Some((matched, rule.name.clone()));
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

        if record.enabled {
            validate_operator(&record.operator)?;
        }

        let decision = RuleMatchDecision::from_rule(record.action, record.nolog);

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
    let mut list_path_needs = HashMap::new();
    let mut regex_keys = HashSet::new();
    let mut needs_network_aliases = false;

    for rule in rules.iter().filter(|rule| rule.enabled) {
        collect_operator_dependencies(
            &rule.operator,
            &mut list_path_needs,
            &mut regex_keys,
            &mut needs_network_aliases,
        );
    }

    let mut caches = RuleMatchCaches::default();

    for (path, needs) in list_path_needs {
        let needs_text_entries = needs.domains
            || needs.trimmed_values
            || needs.networks
            || !needs.regex_sensitivities.is_empty();
        let entries = if needs_text_entries {
            Some(load_list_entries_async(&path).await?)
        } else {
            None
        };

        if needs.domains {
            let mut wildcard_trie = DomainWildcardTrie::default();
            let mut glob_matchers = Vec::new();
            let domains = entries
                .as_ref()
                .expect("entries loaded when domains are required")
                .iter()
                .filter_map(|entry| {
                    let host = normalize_domain_list_entry(entry)?;
                    if let Some(suffix) = wildcard_suffix(&host) {
                        wildcard_trie.insert_suffix(suffix);
                        return None;
                    }
                    if is_domain_glob_pattern(&host) {
                        if let Ok(glob) = Glob::new(&host) {
                            glob_matchers.push(glob.compile_matcher());
                        }
                        return None;
                    }
                    Some(host)
                })
                .collect::<HashSet<_>>();
            caches.list_domains.insert(path.clone(), domains);
            caches
                .list_domain_wildcards
                .insert(path.clone(), wildcard_trie);
            caches.list_domain_globs.insert(path.clone(), glob_matchers);
        }

        if needs.trimmed_values {
            let trimmed_values = entries
                .as_ref()
                .expect("entries loaded when trimmed_values are required")
                .iter()
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>();
            caches
                .list_trimmed_values
                .insert(path.clone(), trimmed_values);
        }

        if needs.networks {
            let mut index = CidrTrieIndex::default();
            for (network, prefix) in entries
                .as_ref()
                .expect("entries loaded when networks are required")
                .iter()
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .filter(|entry| entry.contains('/'))
                .filter_map(<IpAddr as IpAddrNetworkExt>::parse_network_spec)
            {
                index.insert(network, prefix);
            }
            caches.list_networks.insert(path.clone(), index);
        }

        for sensitive in needs.regex_sensitivities {
            let cache = build_list_regex_cache(
                entries
                    .as_ref()
                    .expect("entries loaded when regex cache is required")
                    .iter(),
                sensitive,
            );
            caches
                .list_regexes
                .insert(ListRegexCacheKey::new(&path, sensitive), cache);
        }
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
    list_path_needs: &mut HashMap<PathBuf, ListPathNeeds>,
    regex_keys: &mut HashSet<RegexCacheKey>,
    needs_network_aliases: &mut bool,
) {
    if operator.type_name.eq_ignore_ascii_case("regexp") {
        regex_keys.insert(RegexCacheKey::new(&operator.data, operator.sensitive));
    }

    if operator.type_name.eq_ignore_ascii_case("lists") || operator.operand.starts_with("lists.") {
        let path = PathBuf::from(operator.data.as_str());
        let needs = list_path_needs.entry(path).or_default();
        match operator.operand.as_str() {
            "lists.domains" => needs.domains = true,
            "lists.ips" => {
                needs.trimmed_values = true;
                needs.networks = true;
            }
            "lists.hash.md5" => needs.trimmed_values = true,
            "lists.nets" => {
                needs.trimmed_values = true;
                needs.networks = true;
            }
            "lists.domains_regexp" => {
                needs.regex_sensitivities.insert(operator.sensitive);
            }
            _ => {}
        }
    }

    if operator.type_name.eq_ignore_ascii_case("network") {
        *needs_network_aliases = true;
    }

    for item in &operator.list {
        collect_operator_dependencies(item, list_path_needs, regex_keys, needs_network_aliases);
    }
}

impl ListRegexCache {
    fn matches(&self, candidate: &str) -> bool {
        if self.aho_regexes.is_empty() && self.fallback_regexes.is_empty() {
            return false;
        }

        if let Some(aho) = &self.aho {
            let mut tested = vec![false; self.aho_regexes.len()];
            for mat in aho.find_iter(candidate) {
                let idx = mat.pattern().as_usize();
                if let Some(indices) = self.aho_pattern_to_regex_indices.get(idx) {
                    for regex_idx in indices {
                        if tested[*regex_idx] {
                            continue;
                        }
                        tested[*regex_idx] = true;
                        if self.aho_regexes[*regex_idx].is_match(candidate) {
                            return true;
                        }
                    }
                }
            }

            return self
                .fallback_regexes
                .iter()
                .any(|regex| regex.is_match(candidate));
        }

        self.aho_regexes
            .iter()
            .chain(self.fallback_regexes.iter())
            .any(|regex| regex.is_match(candidate))
    }
}

fn build_list_regex_cache<'a>(
    entries: impl Iterator<Item = &'a String>,
    sensitive: bool,
) -> ListRegexCache {
    let mut aho_regexes = Vec::new();
    let mut fallback_regexes = Vec::new();
    let mut literal_to_indices: HashMap<String, Vec<usize>> = HashMap::new();
    let mut literal_hint_count = 0usize;
    let mut literal_total_len = 0usize;
    let mut total_regex_count = 0usize;

    for entry in entries {
        if let Some(regex) = compile_regex(entry, true) {
            total_regex_count += 1;
            if let Some(literal) = extract_regex_literal_hint(entry, sensitive)
                && is_aho_friendly_regex_pattern(entry)
            {
                let regex_idx = aho_regexes.len();
                literal_total_len += literal.len();
                literal_to_indices
                    .entry(literal)
                    .or_default()
                    .push(regex_idx);
                literal_hint_count += 1;
                aho_regexes.push(regex);
            } else {
                fallback_regexes.push(regex);
            }
        }
    }

    let should_enable_aho =
        should_enable_aho(total_regex_count, literal_hint_count, literal_total_len);

    let (aho, aho_pattern_to_regex_indices) = if !should_enable_aho || literal_to_indices.is_empty()
    {
        fallback_regexes.extend(aho_regexes);
        aho_regexes = Vec::new();
        (None, Vec::new())
    } else {
        let mut literals = literal_to_indices.keys().cloned().collect::<Vec<_>>();
        literals.sort();

        let mut mapping = Vec::with_capacity(literals.len());
        for literal in &literals {
            mapping.push(literal_to_indices.get(literal).cloned().unwrap_or_default());
        }

        let aho = AhoCorasick::new(literals).ok();
        (aho, mapping)
    };

    ListRegexCache {
        aho_regexes,
        fallback_regexes,
        aho,
        aho_pattern_to_regex_indices,
    }
}

fn should_enable_aho(
    total_regex_count: usize,
    literal_hint_count: usize,
    literal_total_len: usize,
) -> bool {
    if total_regex_count < AHO_MIN_REGEXES || literal_hint_count == 0 {
        return false;
    }

    let coverage = (literal_hint_count as f64) / (total_regex_count as f64);
    if coverage < AHO_MIN_LITERAL_COVERAGE {
        return false;
    }

    let avg_literal_len = (literal_total_len as f64) / (literal_hint_count as f64);
    avg_literal_len >= AHO_MIN_AVG_LITERAL_LEN
}

fn is_aho_friendly_regex_pattern(pattern: &str) -> bool {
    !pattern.contains("(?")
}

fn extract_regex_literal_hint(pattern: &str, sensitive: bool) -> Option<String> {
    // Safe literal hint extraction for common anchored forms like ^example\.org$.
    let body = pattern.strip_prefix('^')?.strip_suffix('$')?;
    let mut literal = String::new();
    let mut escaped = false;

    for ch in body.chars() {
        if escaped {
            literal.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if matches!(
            ch,
            '.' | '[' | ']' | '(' | ')' | '{' | '}' | '*' | '+' | '?' | '|' | '^' | '$'
        ) {
            return None;
        }

        literal.push(ch);
    }

    if literal.is_empty() {
        return None;
    }

    Some(if sensitive {
        literal
    } else {
        literal.to_ascii_lowercase()
    })
}

fn normalize_domain_list_entry(entry: &str) -> Option<String> {
    let line = entry.strip_suffix('\r').unwrap_or(entry).trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let host = if let Some(value) = line.strip_prefix("0.0.0.0") {
        value.trim()
    } else if let Some(value) = line.strip_prefix("127.0.0.1") {
        value.trim()
    } else {
        return None;
    };

    if matches!(
        host,
        "local" | "localhost" | "localhost.localdomain" | "broadcasthost"
    ) {
        return None;
    }

    Some(host.to_string())
}

fn wildcard_suffix(host: &str) -> Option<&str> {
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

fn is_domain_glob_pattern(host: &str) -> bool {
    if wildcard_suffix(host).is_some() {
        return false;
    }

    host.contains('?') || host.contains('[') || host.contains(']') || host.contains('*')
}

fn compile_regex(pattern: &str, sensitive: bool) -> Option<Regex> {
    Regex::new(&build_regex_pattern(pattern, sensitive)).ok()
}

fn build_regex_pattern(pattern: &str, sensitive: bool) -> String {
    if sensitive {
        pattern.to_string()
    } else {
        pattern.to_lowercase()
    }
}

async fn load_rules_from_path(
    path: &Path,
) -> Result<(Vec<RuleRecord>, Vec<(String, RuleDuration)>)> {
    let mut loaded = Vec::new();
    let mut temporary_rules = Vec::new();

    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(entries) => entries,
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
        if record.enabled
            && let Err(err) = validate_operator(&record.operator)
        {
            warn!(
                file = %file_path.display(),
                rule = %record.name,
                err = %err,
                "skipping invalid enabled rule"
            );
            continue;
        }
        if record.enabled && record.duration.temporary_spec().is_some() {
            temporary_rules.push((record.name.clone(), record.duration.clone()));
        }
        loaded.push(record);
    }

    loaded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));

    Ok((loaded, temporary_rules))
}

fn validate_operator(operator: &RuleOperator) -> Result<()> {
    if operator.type_name.trim().is_empty()
        && operator.operand.trim().is_empty()
        && operator.data.trim().is_empty()
        && operator.list.is_empty()
    {
        anyhow::bail!("invalid operator");
    }

    if !operator.type_name.eq_ignore_ascii_case("simple")
        && !operator.type_name.eq_ignore_ascii_case("regexp")
        && !operator.type_name.eq_ignore_ascii_case("list")
        && operator.operand != "true"
        && operator.data.trim().is_empty()
    {
        anyhow::bail!(
            "operand {} cannot be empty for type {}",
            operator.operand,
            operator.type_name
        );
    }

    if operator.type_name.eq_ignore_ascii_case("regexp")
        && compile_regex(&operator.data, operator.sensitive).is_none()
    {
        anyhow::bail!("invalid regexp pattern: {}", operator.data);
    }

    if operator.type_name.eq_ignore_ascii_case("simple") && operator.operand == "user.name" {
        let exists = nix::unistd::User::from_name(operator.data.as_str())
            .ok()
            .flatten()
            .is_some();
        if !exists {
            anyhow::bail!("invalid user.name operand: {}", operator.data);
        }
    }

    if operator.type_name.eq_ignore_ascii_case("network")
        && operator.operand != "dest.network"
        && operator.operand != "source.network"
    {
        anyhow::bail!(
            "operand {} is only allowed with type network (dest.network or source.network)",
            operator.operand
        );
    }

    if operator.type_name.eq_ignore_ascii_case("range") {
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

    if operator.type_name.eq_ignore_ascii_case("lists") {
        match operator.operand.as_str() {
            "lists.domains"
            | "lists.domains_regexp"
            | "lists.ips"
            | "lists.nets"
            | "lists.hash.md5" => {}
            _ => anyhow::bail!("unknown lists operand: {}", operator.operand),
        }
    }

    if operator.type_name.eq_ignore_ascii_case("list")
        && operator.list.is_empty()
        && !operator.data.trim().is_empty()
        && serde_json::from_str::<Vec<RuleFileOperator>>(&operator.data).is_err()
    {
        anyhow::bail!("invalid legacy list payload in operator data");
    }

    for sub in &operator.list {
        validate_operator(sub)?;
    }

    Ok(())
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
    load_list_entries_async_plain(path).await
}

#[cfg(test)]
pub(crate) async fn load_list_entries_async_plain_for_test(path: &Path) -> Result<Vec<String>> {
    load_list_entries_async_plain(path).await
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum ListsDomainsRegexpCacheModeForTest {
    AhoAndCompiled,
    CompiledOnly,
}

#[cfg(test)]
pub(crate) fn measure_lists_indexing_latency_for_test(
    operand: &str,
    entries: &[String],
    sensitive: bool,
    regexp_mode: ListsDomainsRegexpCacheModeForTest,
) -> Result<Duration> {
    let start = std::time::Instant::now();
    let _ = build_lists_match_caches_for_test(operand, entries, sensitive, regexp_mode)?;
    Ok(start.elapsed())
}

#[cfg(test)]
pub(crate) fn measure_lists_matching_latency_for_test(
    operand: &str,
    entries: &[String],
    sensitive: bool,
    candidate_ip: &str,
    candidate_host: Option<&str>,
    iterations: usize,
    regexp_mode: ListsDomainsRegexpCacheModeForTest,
) -> Result<(Duration, usize)> {
    let list_path = PathBuf::from("/__lists_bench_path__");
    let caches = build_lists_match_caches_for_test(operand, entries, sensitive, regexp_mode)?;

    let operator = RuleOperator {
        type_name: "lists".to_string(),
        operand: operand.to_string(),
        data: list_path.display().to_string(),
        sensitive,
        list: Vec::new(),
    };

    let attempt = ConnectionAttempt {
        request_id: 1,
        protocol: crate::models::connection_state::TransportProtocol::Tcp,
        src_ip: "127.0.0.1".to_string(),
        src_port: 10000,
        dst_ip: candidate_ip.to_string(),
        dst_port: 443,
        iface_in_idx: 0,
        iface_out_idx: 0,
        dns_query: None,
        pid: 1,
        uid: 1000,
    };
    let process = ProcessInfo {
        pid: 1,
        path: "/usr/bin/curl".to_string(),
        args: vec!["curl".to_string()],
        cwd: None,
        env_preview: Vec::new(),
        process_hash: Some("hash-value".to_string()),
        process_hash_md5: Some("hash-value".to_string()),
        process_hash_sha1: Some("hash-value".to_string()),
        parent_chain: vec![crate::models::process_state::ProcessNode {
            pid: 0,
            path: "/sbin/init".to_string(),
        }],
    };

    let start = std::time::Instant::now();
    let mut hits = 0usize;
    for _ in 0..iterations {
        if operator_matches_lists(&operator, &attempt, &process, candidate_host, &caches) {
            hits += 1;
        }
    }

    Ok((start.elapsed(), hits))
}

#[cfg(test)]
fn build_lists_match_caches_for_test(
    operand: &str,
    entries: &[String],
    sensitive: bool,
    regexp_mode: ListsDomainsRegexpCacheModeForTest,
) -> Result<RuleMatchCaches> {
    let list_path = PathBuf::from("/__lists_bench_path__");
    let mut caches = RuleMatchCaches::default();

    let normalized_entries = entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    match operand {
        "lists.domains" => {
            let mut wildcard_trie = DomainWildcardTrie::default();
            let mut glob_matchers = Vec::new();
            let domains = normalized_entries
                .iter()
                .filter_map(|entry| {
                    let host = normalize_domain_list_entry(entry)?;
                    if let Some(suffix) = wildcard_suffix(&host) {
                        wildcard_trie.insert_suffix(suffix);
                        return None;
                    }
                    if is_domain_glob_pattern(&host) {
                        if let Ok(glob) = Glob::new(&host) {
                            glob_matchers.push(glob.compile_matcher());
                        }
                        return None;
                    }
                    Some(host)
                })
                .collect::<HashSet<_>>();
            caches.list_domains.insert(list_path.clone(), domains);
            caches
                .list_domain_wildcards
                .insert(list_path.clone(), wildcard_trie);
            caches
                .list_domain_globs
                .insert(list_path.clone(), glob_matchers);
        }
        "lists.ips" | "lists.nets" => {
            let trimmed_values = normalized_entries.iter().cloned().collect::<HashSet<_>>();
            caches
                .list_trimmed_values
                .insert(list_path.clone(), trimmed_values);

            let mut index = CidrTrieIndex::default();
            for (network, prefix) in normalized_entries
                .iter()
                .filter(|entry| entry.contains('/'))
                .filter_map(|entry| <IpAddr as IpAddrNetworkExt>::parse_network_spec(entry))
            {
                index.insert(network, prefix);
            }
            caches.list_networks.insert(list_path.clone(), index);
        }
        "lists.domains_regexp" => {
            let cache = match regexp_mode {
                ListsDomainsRegexpCacheModeForTest::AhoAndCompiled => {
                    build_list_regex_cache(normalized_entries.iter(), sensitive)
                }
                ListsDomainsRegexpCacheModeForTest::CompiledOnly => {
                    build_list_regex_cache_compiled_only(normalized_entries.iter())
                }
            };
            caches
                .list_regexes
                .insert(ListRegexCacheKey::new(&list_path, sensitive), cache);
        }
        _ => anyhow::bail!("unsupported benchmark lists operand: {operand}"),
    }

    Ok(caches)
}

#[cfg(test)]
fn build_list_regex_cache_compiled_only<'a>(
    entries: impl Iterator<Item = &'a String>,
) -> ListRegexCache {
    let mut fallback_regexes = Vec::new();
    for entry in entries {
        if let Some(regex) = compile_regex(entry, true) {
            fallback_regexes.push(regex);
        }
    }

    ListRegexCache {
        aho_regexes: Vec::new(),
        fallback_regexes,
        aho: None,
        aho_pattern_to_regex_indices: Vec::new(),
    }
}

async fn load_list_entries_async_plain(path: &Path) -> Result<Vec<String>> {
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
        let file_entries = parse_list_lines(raw.lines());

        entries.extend(file_entries);
    }

    Ok(entries)
}

fn parse_list_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<String> {
    lines
        .filter_map(|line| {
            let normalized = line.strip_suffix('\r').unwrap_or(line);
            if normalized.is_empty() || normalized.starts_with('#') {
                return None;
            }
            Some(normalized.to_string())
        })
        .collect()
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
        let mut operator = operator;
        if operator.r#type.eq_ignore_ascii_case("list")
            && operator.list.is_empty()
            && !operator.data.trim().is_empty()
            && let Ok(decoded) = serde_json::from_str::<Vec<RuleFileOperator>>(&operator.data)
        {
            operator.list = decoded;
            operator.data.clear();
        }

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
    use nix::unistd::{Uid, User};
    use regex::Regex;
    use std::path::PathBuf;

    use crate::models::{
        connection_state::{ConnectionAttempt, TransportProtocol},
        process_state::ProcessNode,
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
            process_hash_md5: Some("hash-value".to_string()),
            process_hash_sha1: Some("hash-value".to_string()),
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
            iface_in_idx: 0,
            iface_out_idx: 0,
            dns_query: None,
            pid: 4242,
            uid: 1000,
        }
    }

    #[test]
    fn regexp_operator_respects_sensitivity_setting() {
        let mut caches = RuleMatchCaches::default();
        let ins_key = RegexCacheKey::new("^example\\.org$", false);
        let sen_key = RegexCacheKey::new("^example\\.org$", true);
        caches.regexes.insert(
            ins_key.clone(),
            Regex::new(&build_regex_pattern(&ins_key.pattern, false))
                .expect("compile insensitive regex"),
        );
        caches.regexes.insert(
            sen_key.clone(),
            Regex::new(&build_regex_pattern(&sen_key.pattern, true))
                .expect("compile sensitive regex"),
        );

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
    fn regexp_insensitive_lowers_pattern_and_candidate_like_go() {
        let mut caches = RuleMatchCaches::default();
        let key = RegexCacheKey::new("^EXAMPLE\\.ORG$", false);
        caches.regexes.insert(
            key.clone(),
            Regex::new(&build_regex_pattern(&key.pattern, key.sensitive))
                .expect("compile go-style lowered regex"),
        );

        let op = RuleOperator {
            type_name: "regexp".to_string(),
            operand: "dest.host".to_string(),
            data: "^EXAMPLE\\.ORG$".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &op,
            &test_attempt("10.0.0.3"),
            &test_process(),
            Some("ExAmPlE.OrG"),
            &caches,
        ));
    }

    #[test]
    fn iface_in_operand_matches_interface_name() {
        let lo = std::ffi::CString::new("lo").expect("static lo cstring");
        // SAFETY: `lo` is NUL-terminated and if_nametoindex does not retain the pointer.
        let lo_idx = unsafe { libc::if_nametoindex(lo.as_ptr()) };
        if lo_idx == 0 {
            return;
        }

        let mut attempt = test_attempt("10.0.0.3");
        attempt.iface_in_idx = lo_idx;

        let op = RuleOperator {
            type_name: "simple".to_string(),
            operand: "iface.in".to_string(),
            data: "lo".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &op,
            &attempt,
            &test_process(),
            None,
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn iface_out_operand_matches_interface_name() {
        let lo = std::ffi::CString::new("lo").expect("static lo cstring");
        // SAFETY: `lo` is NUL-terminated and if_nametoindex does not retain the pointer.
        let lo_idx = unsafe { libc::if_nametoindex(lo.as_ptr()) };
        if lo_idx == 0 {
            return;
        }

        let mut attempt = test_attempt("10.0.0.3");
        attempt.iface_out_idx = lo_idx;

        let op = RuleOperator {
            type_name: "simple".to_string(),
            operand: "iface.out".to_string(),
            data: "lo".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &op,
            &attempt,
            &test_process(),
            None,
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn user_name_operand_matches_current_uid() {
        let Some(user) = User::from_uid(Uid::current()).ok().flatten() else {
            return;
        };

        let mut attempt = test_attempt("10.0.0.3");
        attempt.uid = user.uid.as_raw();

        let op = RuleOperator {
            type_name: "simple".to_string(),
            operand: "user.name".to_string(),
            data: user.name,
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &op,
            &attempt,
            &test_process(),
            None,
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn lists_domain_and_domain_regexp_match_expected_host_values() {
        let list_path = PathBuf::from("/tmp/test-domains");
        let mut caches = RuleMatchCaches::default();
        caches.list_domains.insert(
            list_path.clone(),
            ["example.org".to_string()].into_iter().collect(),
        );
        caches.list_regexes.insert(
            ListRegexCacheKey::new(&list_path, false),
            ListRegexCache {
                aho_regexes: Vec::new(),
                fallback_regexes: vec![
                    Regex::new("(?i:^api\\.example\\.org$)").expect("compile list regex"),
                ],
                aho: None,
                aho_pattern_to_regex_indices: Vec::new(),
            },
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
    fn lists_ips_and_nets_match_expected_destination() {
        let ips_path = PathBuf::from("/tmp/test-ips");
        let nets_path = PathBuf::from("/tmp/test-nets");

        let mut caches = RuleMatchCaches::default();
        caches.list_trimmed_values.insert(
            ips_path.clone(),
            ["10.0.0.4".to_string()].into_iter().collect(),
        );
        caches.list_networks.insert(nets_path.clone(), {
            let mut index = CidrTrieIndex::default();
            index.insert("10.0.0.0".parse().expect("parse test network ip"), 24);
            index
        });

        let ips_op = RuleOperator {
            type_name: "lists".to_string(),
            operand: "lists.ips".to_string(),
            data: ips_path.display().to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let nets_op = RuleOperator {
            operand: "lists.nets".to_string(),
            data: nets_path.display().to_string(),
            ..ips_op.clone()
        };

        let attempt = test_attempt("10.0.0.4");
        let process = test_process();

        assert!(operator_matches_against(
            &ips_op, &attempt, &process, None, &caches,
        ));
        assert!(operator_matches_against(
            &nets_op, &attempt, &process, None, &caches,
        ));
    }

    #[test]
    fn lists_nets_matches_ipv6_prefixes() {
        let nets_path = PathBuf::from("/tmp/test-nets-v6");
        let mut caches = RuleMatchCaches::default();
        caches.list_networks.insert(nets_path.clone(), {
            let mut index = CidrTrieIndex::default();
            index.insert("2001:db8::".parse().expect("parse v6 test network ip"), 32);
            index
        });

        let nets_op = RuleOperator {
            type_name: "lists".to_string(),
            operand: "lists.nets".to_string(),
            data: nets_path.display().to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &nets_op,
            &test_attempt("2001:db8::10"),
            &test_process(),
            None,
            &caches,
        ));
        assert!(!operator_matches_against(
            &nets_op,
            &test_attempt("2001:dead::10"),
            &test_process(),
            None,
            &caches,
        ));
    }

    #[test]
    fn lists_domains_wildcard_fallback_matches_subdomains_only() {
        let list_path = PathBuf::from("/tmp/test-domains-wildcard");
        let mut caches = RuleMatchCaches::default();
        let mut trie = DomainWildcardTrie::default();
        trie.insert_suffix("example.org");
        caches.list_domain_wildcards.insert(list_path.clone(), trie);

        let wildcard_op = RuleOperator {
            type_name: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: list_path.display().to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &wildcard_op,
            &test_attempt("10.0.0.4"),
            &test_process(),
            Some("api.example.org"),
            &caches,
        ));
        assert!(!operator_matches_against(
            &wildcard_op,
            &test_attempt("10.0.0.4"),
            &test_process(),
            Some("example.org"),
            &caches,
        ));
    }

    #[test]
    fn lists_domains_glob_fallback_matches_extended_patterns() {
        let list_path = PathBuf::from("/tmp/test-domains-glob");
        let mut caches = RuleMatchCaches::default();
        let glob = Glob::new("api-??.example.org")
            .expect("compile domain glob")
            .compile_matcher();
        caches
            .list_domain_globs
            .insert(list_path.clone(), vec![glob]);

        let glob_op = RuleOperator {
            type_name: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: list_path.display().to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &glob_op,
            &test_attempt("10.0.0.4"),
            &test_process(),
            Some("api-12.example.org"),
            &caches,
        ));
        assert!(!operator_matches_against(
            &glob_op,
            &test_attempt("10.0.0.4"),
            &test_process(),
            Some("api-123.example.org"),
            &caches,
        ));
    }

    #[test]
    fn list_regex_cache_disables_aho_for_low_literal_coverage() {
        let mut entries = vec!["^api\\.example\\.org$".to_string()];
        for i in 0..256 {
            entries.push(format!(
                "^(?:node|edge)-[a-z0-9]{{4}}\\.zone{}\\.example\\.(?:org|net)$",
                i % 31
            ));
        }

        let cache = build_list_regex_cache(entries.iter(), false);
        assert!(cache.aho.is_none());
        assert!(cache.aho_regexes.is_empty());
        assert!(!cache.fallback_regexes.is_empty());
    }

    #[test]
    fn list_regex_cache_enables_aho_for_high_literal_coverage() {
        let entries = (0..256)
            .map(|i| format!("^host-{i}\\.example\\.org$"))
            .collect::<Vec<_>>();

        let cache = build_list_regex_cache(entries.iter(), false);
        assert!(cache.aho.is_some());
        assert!(!cache.aho_regexes.is_empty());
    }

    #[test]
    fn list_regex_cache_keeps_complex_regex_fallback_when_aho_enabled() {
        let mut entries = (0..256)
            .map(|i| format!("^host-{i}\\.example\\.org$"))
            .collect::<Vec<_>>();
        entries.push("^(?:service|api)-[a-z0-9-]+\\.example\\.org$".to_string());

        let cache = build_list_regex_cache(entries.iter(), false);
        assert!(cache.aho.is_some());
        assert!(!cache.fallback_regexes.is_empty());

        assert!(cache.matches("host-42.example.org"));
        assert!(cache.matches("service-foo.example.org"));
    }

    #[test]
    fn process_hash_sha1_operand_matches_expected_hash() {
        let op = RuleOperator {
            type_name: "simple".to_string(),
            operand: "process.hash.sha1".to_string(),
            data: "hash-value".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(operator_matches_against(
            &op,
            &test_attempt("10.0.0.3"),
            &test_process(),
            None,
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn process_hash_operands_match_when_checksums_missing() {
        let mut process = test_process();
        process.process_hash_md5 = None;
        process.process_hash_sha1 = None;

        let md5_op = RuleOperator {
            type_name: "simple".to_string(),
            operand: "process.hash.md5".to_string(),
            data: "anything".to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let sha1_op = RuleOperator {
            operand: "process.hash.sha1".to_string(),
            ..md5_op.clone()
        };

        assert!(operator_matches_against(
            &md5_op,
            &test_attempt("10.0.0.3"),
            &process,
            None,
            &RuleMatchCaches::default(),
        ));
        assert!(operator_matches_against(
            &sha1_op,
            &test_attempt("10.0.0.3"),
            &process,
            None,
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn validate_operator_accepts_source_network_operand() {
        let op = RuleOperator {
            type_name: "network".to_string(),
            operand: "source.network".to_string(),
            data: "10.0.0.0/8".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(validate_operator(&op).is_ok());
    }

    #[test]
    fn validate_operator_rejects_invalid_network_operand() {
        let op = RuleOperator {
            type_name: "network".to_string(),
            operand: "dest.host".to_string(),
            data: "10.0.0.0/8".to_string(),
            sensitive: false,
            list: Vec::new(),
        };

        assert!(validate_operator(&op).is_err());
    }

    #[test]
    fn simple_operands_match_expected_fields() {
        let attempt = test_attempt("185.53.178.14");
        let process = test_process();

        let process_id = RuleOperator {
            type_name: "simple".to_string(),
            operand: "process.id".to_string(),
            data: process.pid.to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let process_path = RuleOperator {
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            ..process_id.clone()
        };
        let process_cmd = RuleOperator {
            operand: "process.command".to_string(),
            data: "CURL".to_string(),
            ..process_id.clone()
        };
        let dst_ip = RuleOperator {
            operand: "dest.ip".to_string(),
            data: "185.53.178.14".to_string(),
            ..process_id.clone()
        };
        let user_id = RuleOperator {
            operand: "user.id".to_string(),
            data: attempt.uid.to_string(),
            ..process_id.clone()
        };

        assert!(operator_matches_against(
            &process_id,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
        assert!(operator_matches_against(
            &process_path,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
        assert!(operator_matches_against(
            &process_cmd,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
        assert!(operator_matches_against(
            &dst_ip,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
        assert!(operator_matches_against(
            &user_id,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn source_operands_match_expected_fields() {
        let attempt = test_attempt("10.0.0.3");
        let process = test_process();

        let src_ip = RuleOperator {
            type_name: "simple".to_string(),
            operand: "source.ip".to_string(),
            data: attempt.src_ip.clone(),
            sensitive: false,
            list: Vec::new(),
        };
        let src_port = RuleOperator {
            operand: "source.port".to_string(),
            data: attempt.src_port.to_string(),
            ..src_ip.clone()
        };

        assert!(operator_matches_against(
            &src_ip,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
        assert!(operator_matches_against(
            &src_port,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn simple_process_path_sensitive_mismatch_fails() {
        let op = RuleOperator {
            type_name: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/OpenSnitchd".to_string(),
            sensitive: true,
            list: Vec::new(),
        };

        assert!(!operator_matches_against(
            &op,
            &test_attempt("10.0.0.3"),
            &test_process(),
            Some("opensnitch.io"),
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn bare_ip_no_host_matches_empty_host_operands() {
        let mut caches = RuleMatchCaches::default();
        let regex_key = RegexCacheKey::new("^$", true);
        caches.regexes.insert(
            regex_key.clone(),
            Regex::new(&build_regex_pattern(&regex_key.pattern, true))
                .expect("compile empty-host regex"),
        );

        let simple_empty = RuleOperator {
            type_name: "simple".to_string(),
            operand: "dest.host".to_string(),
            data: String::new(),
            sensitive: true,
            list: Vec::new(),
        };
        let regexp_empty = RuleOperator {
            type_name: "regexp".to_string(),
            operand: "dest.host".to_string(),
            data: "^$".to_string(),
            sensitive: true,
            list: Vec::new(),
        };

        let attempt = test_attempt("10.0.0.3");
        let process = test_process();

        assert!(operator_matches_against(
            &simple_empty,
            &attempt,
            &process,
            Some(""),
            &caches,
        ));
        assert!(operator_matches_against(
            &regexp_empty,
            &attempt,
            &process,
            Some(""),
            &caches,
        ));
    }

    #[test]
    fn network_operator_matches_and_mismatches_expected_cidr() {
        let match_op = RuleOperator {
            type_name: "network".to_string(),
            operand: "dest.network".to_string(),
            data: "185.53.178.14/24".to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let miss_op = RuleOperator {
            data: "8.8.8.8/24".to_string(),
            ..match_op.clone()
        };

        let attempt = test_attempt("185.53.178.14");
        let process = test_process();

        assert!(operator_matches_against(
            &match_op,
            &attempt,
            &process,
            None,
            &RuleMatchCaches::default(),
        ));
        assert!(!operator_matches_against(
            &miss_op,
            &attempt,
            &process,
            None,
            &RuleMatchCaches::default(),
        ));
    }

    #[test]
    fn list_operator_requires_all_children_to_match() {
        let mut caches = RuleMatchCaches::default();
        let regex_key = RegexCacheKey::new("^/usr/bin/.*", false);
        caches.regexes.insert(
            regex_key.clone(),
            Regex::new(&build_regex_pattern(&regex_key.pattern, false))
                .expect("compile list child regex"),
        );

        let list_op = RuleOperator {
            type_name: "list".to_string(),
            operand: "list".to_string(),
            data: String::new(),
            sensitive: false,
            list: vec![
                RuleOperator {
                    type_name: "regexp".to_string(),
                    operand: "process.path".to_string(),
                    data: "^/usr/bin/.*".to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
                RuleOperator {
                    type_name: "simple".to_string(),
                    operand: "dest.ip".to_string(),
                    data: "185.53.178.14".to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
                RuleOperator {
                    type_name: "simple".to_string(),
                    operand: "dest.port".to_string(),
                    data: "443".to_string(),
                    sensitive: false,
                    list: Vec::new(),
                },
            ],
        };

        let attempt = test_attempt("185.53.178.14");
        let process = test_process();

        assert!(operator_matches_against(
            &list_op,
            &attempt,
            &process,
            Some("opensnitch.io"),
            &caches,
        ));
    }

    #[test]
    fn range_validation_mirrors_go_edge_cases() {
        let valid = RuleOperator {
            type_name: "range".to_string(),
            operand: "dest.port".to_string(),
            data: "1 - 5000".to_string(),
            sensitive: false,
            list: Vec::new(),
        };
        let invalid_desc = RuleOperator {
            data: "89-80".to_string(),
            ..valid.clone()
        };
        let invalid_open_min = RuleOperator {
            data: "-80".to_string(),
            ..valid.clone()
        };
        let invalid_open_max = RuleOperator {
            data: "53-".to_string(),
            ..valid
        };

        assert!(validate_operator(&invalid_desc).is_err());
        assert!(validate_operator(&invalid_open_min).is_err());
        assert!(validate_operator(&invalid_open_max).is_err());
        assert!(
            validate_operator(&RuleOperator {
                type_name: "range".to_string(),
                operand: "dest.port".to_string(),
                data: "1 - 5000".to_string(),
                sensitive: false,
                list: Vec::new(),
            })
            .is_ok()
        );
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

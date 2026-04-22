use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::ErrorKind,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use opensnitch_proto::pb;
use regex::Regex;
use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use crate::utils::net_iface::interface_name_by_index;

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

    pub(crate) fn to_summary_rule(self) -> pb::Rule {
        pb::Rule {
            created: 0,
            name: "runtime-match".to_owned(),
            description: "matched existing runtime rule".to_owned(),
            enabled: true,
            precedence: false,
            nolog: self.nolog,
            action: if self.allow {
                "allow".to_owned()
            } else if self.reject {
                "reject".to_owned()
            } else {
                "deny".to_owned()
            },
            duration: "always".to_owned(),
            operator: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RegexCacheKey {
    pub(crate) pattern: String,
    pub(crate) sensitive: bool,
}

impl RegexCacheKey {
    pub(crate) fn new(pattern: &str, sensitive: bool) -> Self {
        Self {
            pattern: pattern.to_string(),
            sensitive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ListRegexCacheKey {
    pub(crate) path: PathBuf,
    pub(crate) sensitive: bool,
}

impl ListRegexCacheKey {
    pub(crate) fn new(path: &Path, sensitive: bool) -> Self {
        Self {
            path: path.to_path_buf(),
            sensitive,
        }
    }
}

#[derive(Default)]
pub(crate) struct DomainWildcardTrieNode {
    children: HashMap<String, DomainWildcardTrieNode>,
    min_host_labels_required: Option<usize>,
}

#[derive(Default)]
pub(crate) struct DomainWildcardTrie {
    root: DomainWildcardTrieNode,
}

impl DomainWildcardTrie {
    pub(crate) fn insert_suffix(&mut self, suffix: &str) {
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
        let label_count = host.split('.').filter(|label| !label.is_empty()).count();
        if label_count == 0 {
            return false;
        }

        let mut node = &self.root;
        for label in host.rsplit('.').filter(|label| !label.is_empty()) {
            let Some(next) = node.children.get(label) else {
                return false;
            };
            node = next;
            if let Some(min_required) = node.min_host_labels_required
                && label_count >= min_required
            {
                return true;
            }
        }

        false
    }
}

#[derive(Default)]
pub(crate) struct CidrTrieNode {
    terminal: bool,
    zero: Option<Box<CidrTrieNode>>,
    one: Option<Box<CidrTrieNode>>,
}

#[derive(Default)]
pub(crate) struct CidrTrieIndex {
    has_entries: bool,
    v4: CidrTrieNode,
    v6: CidrTrieNode,
}

impl CidrTrieIndex {
    pub(crate) fn insert(&mut self, network: IpAddr, prefix_len: u8) {
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

#[derive(Clone)]
pub(crate) struct ListRegexCache {
    pub(crate) aho_regexes: Vec<Regex>,
    pub(crate) fallback_regexes: Vec<Regex>,
    pub(crate) aho: Option<AhoCorasick>,
    pub(crate) aho_pattern_to_regex_indices: Vec<Vec<usize>>,
}

const AHO_MIN_REGEXES: usize = 128;
const AHO_MIN_LITERAL_COVERAGE: f64 = 0.6;
const AHO_MIN_AVG_LITERAL_LEN: f64 = 6.0;

#[derive(Default)]
pub(crate) struct ListPathSlotCache {
    pub(crate) domains: HashSet<String>,
    pub(crate) domain_wildcards: DomainWildcardTrie,
    pub(crate) domain_globs: Vec<GlobMatcher>,
    pub(crate) trimmed_values: HashSet<String>,
    pub(crate) networks: CidrTrieIndex,
    pub(crate) regex_sensitive: Option<ListRegexCache>,
    pub(crate) regex_insensitive: Option<ListRegexCache>,
}

#[derive(Default)]
pub(crate) struct RuleMatchCaches {
    pub(crate) list_domains: HashMap<PathBuf, HashSet<String>>,
    pub(crate) list_domain_wildcards: HashMap<PathBuf, DomainWildcardTrie>,
    pub(crate) list_domain_globs: HashMap<PathBuf, Vec<GlobMatcher>>,
    pub(crate) list_trimmed_values: HashMap<PathBuf, HashSet<String>>,
    pub(crate) list_networks: HashMap<PathBuf, CidrTrieIndex>,
    pub(crate) list_regexes: HashMap<ListRegexCacheKey, ListRegexCache>,
    pub(crate) list_regexes_sensitive_fast: HashMap<PathBuf, ListRegexCache>,
    pub(crate) list_regexes_insensitive_fast: HashMap<PathBuf, ListRegexCache>,
    pub(crate) network_aliases: HashMap<String, Vec<String>>,
    pub(crate) regexes: HashMap<RegexCacheKey, Regex>,
    pub(crate) regexes_sensitive_fast: HashMap<String, Regex>,
    pub(crate) regexes_insensitive_fast: HashMap<String, Regex>,
    pub(crate) user_name_uid: HashMap<String, Option<u32>>,
    pub(crate) range_bounds: HashMap<String, Option<(u64, u64)>>,
    pub(crate) network_specs_compiled: HashMap<String, Vec<(IpAddr, u8)>>,
    pub(crate) list_slot_by_path: HashMap<PathBuf, usize>,
    pub(crate) list_slots: Vec<ListPathSlotCache>,
}

#[derive(Debug, Clone, Default)]
struct ListPathNeeds {
    domains: bool,
    trimmed_values: bool,
    networks: bool,
    regex_sensitivities: HashSet<bool>,
}

#[derive(Debug, Clone, Default)]
struct OperatorNeeds {
    user_name_values: HashSet<String>,
    range_values: HashSet<String>,
    network_values: HashSet<String>,
}

struct ActiveRuleCompiled {
    name: String,
    operator: RuleOperator,
    decision: RuleMatchDecision,
    terminal_on_match: bool,
    dispatch: ActiveOperatorDispatch,
}

enum ActiveOperatorDispatch {
    Generic,
    AlwaysTrue,
    SimpleHashOptional,
    ListComposite,
    ProcessParentPath,
    UserName,
    ProcessEnv {
        key: String,
    },
    ProcessCommandDirect,
    Lists {
        operand: CompiledListOperand,
        slot_idx: Option<usize>,
        source_scope: bool,
    },
    Network {
        source: bool,
    },
    Range {
        numeric_operand: Option<NumericOperandKind>,
        bounds: Option<(u64, u64)>,
    },
    SimpleNumeric {
        operand: NumericOperandKind,
        expected: u64,
    },
}

enum CompiledListOperand {
    Domains,
    DomainsRegexp,
    Ips,
    HashMd5,
    Nets,
    Other,
}

#[derive(Clone, Copy)]
enum NumericOperandKind {
    ProcessId,
    UserId,
    DestPort,
    SourcePort,
}

struct AttemptDerived {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_ip_text: OnceLock<String>,
    dst_ip_text: OnceLock<String>,
}

#[derive(Default, Clone, Copy)]
struct AttemptTextNeeds {
    src_ip_text: bool,
    dst_ip_text: bool,
}

impl Default for AttemptDerived {
    fn default() -> Self {
        Self {
            src_addr: None,
            dst_addr: None,
            src_ip_text: OnceLock::new(),
            dst_ip_text: OnceLock::new(),
        }
    }
}

impl AttemptDerived {
    fn from_attempt(attempt: &ConnectionAttempt) -> Self {
        Self {
            src_addr: Some(attempt.src_addr),
            dst_addr: Some(attempt.dst_addr),
            src_ip_text: OnceLock::new(),
            dst_ip_text: OnceLock::new(),
        }
    }

    fn src_ip_text(&self) -> &str {
        self.src_ip_text
            .get_or_init(|| {
                self.src_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default()
            })
            .as_str()
    }

    fn dst_ip_text(&self) -> &str {
        self.dst_ip_text
            .get_or_init(|| {
                self.dst_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default()
            })
            .as_str()
    }

    fn prewarm(&self, needs: AttemptTextNeeds) {
        if needs.src_ip_text {
            let _ = self.src_ip_text();
        }
        if needs.dst_ip_text {
            let _ = self.dst_ip_text();
        }
    }
}

#[derive(Default)]
struct RuleSnapshot {
    rules_path: Arc<PathBuf>,
    rules: Vec<RuleRecord>,
    active_rules: Vec<ActiveRuleCompiled>,
    attempt_text_needs: AttemptTextNeeds,
    proto_rules: Arc<Vec<pb::Rule>>,
    caches: RuleMatchCaches,
}

#[derive(Clone)]
pub struct RuleService {
    snapshot_tx: watch::Sender<Arc<RuleSnapshot>>,
    snapshot_rx: watch::Receiver<Arc<RuleSnapshot>>,
    update_lock: Arc<Mutex<()>>,
}

impl Default for RuleService {
    fn default() -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(RuleSnapshot::default()));
        Self {
            snapshot_tx,
            snapshot_rx,
            update_lock: Arc::new(Mutex::new(())),
        }
    }
}

impl RuleService {
    fn snapshot(&self) -> Arc<RuleSnapshot> {
        self.snapshot_rx.borrow().clone()
    }

    fn publish_snapshot(&self, next: RuleSnapshot) {
        self.snapshot_tx.send_replace(Arc::new(next));
    }

    #[cfg(test)]
    pub(crate) fn probe_operator_matches_against(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        Self::operator_matches_against(operator, attempt, process, dst_host, caches)
    }

    #[cfg(test)]
    pub(crate) fn probe_build_list_regex_cache<'a>(
        entries: impl Iterator<Item = &'a String>,
        sensitive: bool,
    ) -> ListRegexCache {
        RuleService::build_list_regex_cache(entries, sensitive)
    }

    #[cfg(test)]
    pub(crate) fn probe_build_regex_pattern(pattern: &str, sensitive: bool) -> String {
        RuleService::build_regex_pattern(pattern, sensitive)
    }

    #[cfg(test)]
    pub(crate) fn probe_validate_operator(operator: &RuleOperator) -> Result<()> {
        Self::validate_operator(operator)
    }

    #[cfg(test)]
    pub(crate) async fn probe_load_list_entries_async_plain(path: &Path) -> Result<Vec<String>> {
        Self::load_list_entries_async_plain(path).await
    }

    #[cfg(test)]
    pub(crate) fn probe_measure_lists_indexing_latency(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        regexp_mode: ListsDomainsRegexpCacheMode,
    ) -> Result<Duration> {
        Self::bench_measure_lists_indexing_latency(operand, entries, sensitive, regexp_mode)
    }

    #[cfg(test)]
    pub(crate) fn probe_measure_lists_matching_latency(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        candidate_ip: &str,
        candidate_host: Option<&str>,
        iterations: usize,
        regexp_mode: ListsDomainsRegexpCacheMode,
    ) -> Result<(Duration, usize)> {
        Self::bench_measure_lists_matching_latency(
            operand,
            entries,
            sensitive,
            candidate_ip,
            candidate_host,
            iterations,
            regexp_mode,
        )
    }
}

impl RuleService {
    fn collect_attempt_text_needs(operator: &RuleOperator, needs: &mut AttemptTextNeeds) {
        match operator.operand.as_str() {
            "source.ip" => needs.src_ip_text = true,
            "dest.ip" => needs.dst_ip_text = true,
            "source.network" if !operator.type_name.eq_ignore_ascii_case("network") => {
                needs.src_ip_text = true
            }
            "dest.network" if !operator.type_name.eq_ignore_ascii_case("network") => {
                needs.dst_ip_text = true
            }
            "lists.ips" | "lists.nets"
                if operator.type_name.eq_ignore_ascii_case("lists")
                    || operator.operand.starts_with("lists.") =>
            {
                if Self::list_scope_is_source(operator) {
                    needs.src_ip_text = true;
                } else {
                    needs.dst_ip_text = true;
                }
            }
            _ => {}
        }

        for sub in &operator.list {
            Self::collect_attempt_text_needs(sub, needs);
        }
    }

    fn list_scope_is_source(operator: &RuleOperator) -> bool {
        let Some(scope) = operator.scope.as_deref() else {
            return false;
        };

        // Fast-path: absent scope means default destination behavior.
        scope.eq_ignore_ascii_case("src")
    }

    fn list_candidate_ip_text<'a>(derived: &'a AttemptDerived, source: bool) -> &'a str {
        if source {
            derived.src_ip_text()
        } else {
            derived.dst_ip_text()
        }
    }

    fn list_candidate_ip_addr(derived: &AttemptDerived, source: bool) -> Option<IpAddr> {
        if source {
            derived.src_addr
        } else {
            derived.dst_addr
        }
    }

    fn compile_active_operator_dispatch(
        operator: &RuleOperator,
        caches: &RuleMatchCaches,
    ) -> ActiveOperatorDispatch {
        let operand = operator.operand.as_str();
        let type_name = operator.type_name.as_str();
        let is_simple = type_name.eq_ignore_ascii_case("simple");
        let is_list = type_name.eq_ignore_ascii_case("list");
        let is_regexp = type_name.eq_ignore_ascii_case("regexp");
        let is_range = type_name.eq_ignore_ascii_case("range");
        let is_lists = type_name.eq_ignore_ascii_case("lists");
        let is_network = type_name.eq_ignore_ascii_case("network");

        if operand == "true" {
            return ActiveOperatorDispatch::AlwaysTrue;
        }

        if is_simple && matches!(operand, "process.hash.md5" | "process.hash.sha1") {
            return ActiveOperatorDispatch::SimpleHashOptional;
        }

        if operand == "list" || is_list {
            return ActiveOperatorDispatch::ListComposite;
        }

        if operand == "process.parent.path" {
            return ActiveOperatorDispatch::ProcessParentPath;
        }

        if operand == "user.name" {
            return ActiveOperatorDispatch::UserName;
        }

        if let Some(key) = operand.strip_prefix("process.env.") {
            return ActiveOperatorDispatch::ProcessEnv {
                key: key.to_string(),
            };
        }

        if operand == "process.command" && !is_regexp && !is_range {
            return ActiveOperatorDispatch::ProcessCommandDirect;
        }

        if is_lists || operand.starts_with("lists.") {
            let slot_idx = caches
                .list_slot_by_path
                .get(Path::new(operator.data.as_str()))
                .copied();
            let source_scope = Self::list_scope_is_source(operator);
            let operand = match operand {
                "lists.domains" => CompiledListOperand::Domains,
                "lists.domains_regexp" => CompiledListOperand::DomainsRegexp,
                "lists.ips" => CompiledListOperand::Ips,
                "lists.hash.md5" => CompiledListOperand::HashMd5,
                "lists.nets" => CompiledListOperand::Nets,
                _ => CompiledListOperand::Other,
            };
            return ActiveOperatorDispatch::Lists {
                operand,
                slot_idx,
                source_scope,
            };
        }

        if is_network {
            return ActiveOperatorDispatch::Network {
                source: operand == "source.network",
            };
        }

        if is_range {
            return ActiveOperatorDispatch::Range {
                numeric_operand: Self::numeric_operand_from_str(operand),
                bounds: caches
                    .range_bounds
                    .get(operator.data.as_str())
                    .copied()
                    .flatten()
                    .or_else(|| Self::parse_range_bounds(&operator.data)),
            };
        }

        if is_simple
            && let Some(numeric_operand) = Self::numeric_operand_from_str(operand)
            && let Ok(expected) = operator.data.trim().parse::<u64>()
        {
            return ActiveOperatorDispatch::SimpleNumeric {
                operand: numeric_operand,
                expected,
            };
        }

        ActiveOperatorDispatch::Generic
    }

    fn numeric_operand_from_str(operand: &str) -> Option<NumericOperandKind> {
        match operand {
            "process.id" => Some(NumericOperandKind::ProcessId),
            "user.id" => Some(NumericOperandKind::UserId),
            "dest.port" => Some(NumericOperandKind::DestPort),
            "source.port" => Some(NumericOperandKind::SourcePort),
            _ => None,
        }
    }

    fn numeric_operand_value(
        kind: NumericOperandKind,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
    ) -> u64 {
        match kind {
            NumericOperandKind::ProcessId => u64::from(process.pid),
            NumericOperandKind::UserId => u64::from(attempt.uid),
            NumericOperandKind::DestPort => u64::from(attempt.dst_port),
            NumericOperandKind::SourcePort => u64::from(attempt.src_port),
        }
    }

    fn operator_matches_compiled_rule(
        compiled: &ActiveRuleCompiled,
        attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        match &compiled.dispatch {
            ActiveOperatorDispatch::AlwaysTrue => true,
            ActiveOperatorDispatch::SimpleHashOptional => {
                let Some(hash) = Self::operator_operand_value(
                    &compiled.operator,
                    attempt,
                    derived,
                    process,
                    dst_host,
                ) else {
                    return true;
                };
                Self::operator_matches_text(&compiled.operator, hash.as_ref(), caches)
            }
            ActiveOperatorDispatch::ListComposite => compiled.operator.list.iter().all(|item| {
                Self::operator_matches_against(item, attempt, process, dst_host, caches)
            }),
            ActiveOperatorDispatch::ProcessParentPath => {
                process.parent_chain.iter().any(|parent| {
                    Self::operator_matches_text(&compiled.operator, parent.path.as_str(), caches)
                })
            }
            ActiveOperatorDispatch::UserName => {
                let Some(uid) = caches
                    .user_name_uid
                    .get(compiled.operator.data.as_str())
                    .copied()
                    .flatten()
                    .or_else(|| {
                        nix::unistd::User::from_name(compiled.operator.data.as_str())
                            .ok()
                            .flatten()
                            .map(|user| user.uid.as_raw())
                    })
                else {
                    return false;
                };
                attempt.uid == uid
            }
            ActiveOperatorDispatch::ProcessEnv { key } => {
                let env_value = Self::env_preview_get(process, key).unwrap_or("");
                Self::operator_matches_text(&compiled.operator, env_value, caches)
            }
            ActiveOperatorDispatch::ProcessCommandDirect => Self::matches_joined_args(
                &process.args,
                &compiled.operator.data,
                compiled.operator.sensitive,
            ),
            ActiveOperatorDispatch::Lists {
                operand,
                slot_idx,
                source_scope,
            } => Self::operator_matches_lists_compiled(
                &compiled.operator,
                operand,
                *slot_idx,
                *source_scope,
                attempt,
                derived,
                process,
                dst_host,
                caches,
            ),
            ActiveOperatorDispatch::Network { source } => {
                Self::operator_matches_network_with_derived(
                    &compiled.operator,
                    *source,
                    derived,
                    caches,
                )
            }
            ActiveOperatorDispatch::Range {
                numeric_operand,
                bounds,
            } => {
                if let Some(kind) = numeric_operand {
                    let Some((min, max)) = bounds else {
                        return false;
                    };
                    let candidate = Self::numeric_operand_value(*kind, attempt, process);
                    return candidate >= *min && candidate <= *max;
                }

                let Some(candidate) = Self::operator_operand_value(
                    &compiled.operator,
                    attempt,
                    derived,
                    process,
                    dst_host,
                ) else {
                    return false;
                };
                Self::matches_range_spec(candidate.as_ref(), &compiled.operator.data)
            }
            ActiveOperatorDispatch::SimpleNumeric { operand, expected } => {
                Self::numeric_operand_value(*operand, attempt, process) == *expected
            }
            ActiveOperatorDispatch::Generic => Self::operator_matches_against_with_derived(
                &compiled.operator,
                attempt,
                derived,
                process,
                dst_host,
                caches,
            ),
        }
    }

    fn operator_matches_lists_compiled(
        operator: &RuleOperator,
        compiled_operand: &CompiledListOperand,
        slot_idx: Option<usize>,
        source_scope: bool,
        attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let Some(slot_idx) = slot_idx else {
            return Self::operator_matches_lists(
                operator, attempt, derived, process, dst_host, caches,
            );
        };
        let Some(slot) = caches.list_slots.get(slot_idx) else {
            return Self::operator_matches_lists(
                operator, attempt, derived, process, dst_host, caches,
            );
        };

        let ip_text = Self::list_candidate_ip_text(derived, source_scope);
        let ip_addr = Self::list_candidate_ip_addr(derived, source_scope);

        match compiled_operand {
            CompiledListOperand::Domains => {
                let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty())
                else {
                    return false;
                };
                let lowered_host;
                if !operator.sensitive && Self::has_ascii_uppercase(host) {
                    lowered_host = host.to_ascii_lowercase();
                    host = lowered_host.as_str();
                }
                slot.domains.contains(host)
                    || slot.domain_wildcards.matches_host(host)
                    || slot.domain_globs.iter().any(|glob| glob.is_match(host))
            }
            CompiledListOperand::DomainsRegexp => {
                let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty())
                else {
                    return false;
                };
                let lowered_host;
                if !operator.sensitive && Self::has_ascii_uppercase(host) {
                    lowered_host = host.to_ascii_lowercase();
                    host = lowered_host.as_str();
                }
                let regex_cache = if operator.sensitive {
                    slot.regex_sensitive.as_ref()
                } else {
                    slot.regex_insensitive.as_ref()
                };
                regex_cache
                    .map(|cache| cache.matches(host))
                    .unwrap_or(false)
            }
            CompiledListOperand::Ips => {
                slot.trimmed_values.contains(ip_text)
                    || ip_addr
                        .filter(|_| slot.networks.has_entries())
                        .map(|ip| slot.networks.contains(ip))
                        .unwrap_or(false)
            }
            CompiledListOperand::HashMd5 => {
                let Some(hash) = process.process_hash_md5.as_deref() else {
                    return false;
                };
                slot.trimmed_values.contains(hash.trim())
            }
            CompiledListOperand::Nets => {
                if slot.trimmed_values.contains(ip_text) {
                    return true;
                }
                ip_addr
                    .filter(|_| slot.networks.has_entries())
                    .map(|ip| slot.networks.contains(ip))
                    .unwrap_or(false)
            }
            CompiledListOperand::Other => {
                Self::operator_matches_lists(operator, attempt, derived, process, dst_host, caches)
            }
        }
    }

    fn operator_matches_against(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let derived = AttemptDerived::from_attempt(attempt);
        Self::operator_matches_against_with_derived(
            operator, attempt, &derived, process, dst_host, caches,
        )
    }

    fn operator_matches_against_with_derived(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
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
            let Some(hash) =
                Self::operator_operand_value(operator, attempt, derived, process, dst_host)
            else {
                // Go hash operators return true when checksum data is unavailable.
                return true;
            };
            return Self::operator_matches_text(operator, hash.as_ref(), caches);
        }

        if operator.operand == "list" || operator.type_name.eq_ignore_ascii_case("list") {
            return operator.list.iter().all(|item| {
                Self::operator_matches_against_with_derived(
                    item, attempt, derived, process, dst_host, caches,
                )
            });
        }

        if operator.operand == "process.parent.path" {
            return process
                .parent_chain
                .iter()
                .any(|parent| Self::operator_matches_text(operator, parent.path.as_str(), caches));
        }

        if operator.operand == "user.name" {
            let Some(uid) = caches
                .user_name_uid
                .get(operator.data.as_str())
                .copied()
                .flatten()
                .or_else(|| {
                    nix::unistd::User::from_name(operator.data.as_str())
                        .ok()
                        .flatten()
                        .map(|user| user.uid.as_raw())
                })
            else {
                return false;
            };
            return attempt.uid == uid;
        }

        if let Some(env_key) = operator.operand.strip_prefix("process.env.") {
            let env_value = Self::env_preview_get(process, env_key).unwrap_or("");
            return Self::operator_matches_text(operator, env_value, caches);
        }

        if operator.operand == "process.command"
            && !operator.type_name.eq_ignore_ascii_case("regexp")
            && !operator.type_name.eq_ignore_ascii_case("range")
        {
            return Self::matches_joined_args(&process.args, &operator.data, operator.sensitive);
        }

        if operator.type_name.eq_ignore_ascii_case("lists")
            || operator.operand.starts_with("lists.")
        {
            return RuleService::operator_matches_lists(
                operator, attempt, derived, process, dst_host, caches,
            );
        }

        if operator.type_name.eq_ignore_ascii_case("network") {
            return Self::operator_matches_network(operator, derived, caches);
        }

        if operator.type_name.eq_ignore_ascii_case("range") {
            if let Some(candidate) =
                Self::operator_numeric_value(&operator.operand, attempt, process)
            {
                let Some((min, max)) = caches
                    .range_bounds
                    .get(operator.data.as_str())
                    .copied()
                    .flatten()
                    .or_else(|| Self::parse_range_bounds(&operator.data))
                else {
                    return false;
                };
                return candidate >= min && candidate <= max;
            }
            let Some(candidate) =
                Self::operator_operand_value(operator, attempt, derived, process, dst_host)
            else {
                return false;
            };
            return Self::matches_range_spec(candidate.as_ref(), &operator.data);
        }

        if operator.type_name.eq_ignore_ascii_case("simple")
            && let Some(candidate) =
                Self::operator_numeric_value(&operator.operand, attempt, process)
        {
            let Some(expected) = operator.data.trim().parse::<u64>().ok() else {
                return false;
            };
            return candidate == expected;
        }

        let Some(candidate) =
            Self::operator_operand_value(operator, attempt, derived, process, dst_host)
        else {
            return false;
        };

        Self::operator_matches_text(operator, candidate.as_ref(), caches)
    }

    fn operator_operand_value<'a>(
        operator: &RuleOperator,
        attempt: &'a ConnectionAttempt,
        derived: &'a AttemptDerived,
        process: &'a ProcessInfo,
        dst_host: Option<&'a str>,
    ) -> Option<Cow<'a, str>> {
        match operator.operand.as_str() {
            "process.path" => Some(Cow::Borrowed(process.path.as_str())),
            "process.command" => Some(Cow::Owned(process.args.join(" "))),
            "process.parent.path" => process
                .parent_chain
                .first()
                .map(|node| Cow::Borrowed(node.path.as_str())),
            "process.id" => Some(Cow::Owned(process.pid.to_string())),
            "process.hash.sha1" => process.process_hash_sha1.as_deref().map(Cow::Borrowed),
            "process.hash.md5" => process.process_hash_md5.as_deref().map(Cow::Borrowed),
            "user.id" => Some(Cow::Owned(attempt.uid.to_string())),
            "dest.ip" => Some(Cow::Borrowed(derived.dst_ip_text())),
            "dest.network" => Some(Cow::Borrowed(derived.dst_ip_text())),
            "dest.host" => dst_host.map(Cow::Borrowed),
            "dest.port" => Some(Cow::Owned(attempt.dst_port.to_string())),
            "source.ip" => Some(Cow::Borrowed(derived.src_ip_text())),
            "source.network" => Some(Cow::Borrowed(derived.src_ip_text())),
            "source.port" => Some(Cow::Owned(attempt.src_port.to_string())),
            "iface.in" => interface_name_by_index(attempt.iface_in_idx).map(Cow::Owned),
            "iface.out" => interface_name_by_index(attempt.iface_out_idx).map(Cow::Owned),
            "protocol" => Some(Cow::Borrowed(match attempt.protocol {
                crate::models::connection_state::TransportProtocol::Tcp => "TCP",
                crate::models::connection_state::TransportProtocol::Udp => "UDP",
                crate::models::connection_state::TransportProtocol::UdpLite => "UDPLITE",
                crate::models::connection_state::TransportProtocol::Sctp => "SCTP",
                crate::models::connection_state::TransportProtocol::Icmp => "ICMP",
            })),
            _ => None,
        }
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
            } else if candidate.chars().any(|ch| ch.is_uppercase()) {
                lowered = candidate.to_lowercase();
                lowered.as_str()
            } else {
                candidate
            };

            let fast_map = if operator.sensitive {
                &caches.regexes_sensitive_fast
            } else {
                &caches.regexes_insensitive_fast
            };
            if let Some(regex) = fast_map.get(operator.data.as_str()) {
                return regex.is_match(value);
            }

            return caches
                .regexes
                .get(&RegexCacheKey::new(&operator.data, operator.sensitive))
                .map(|regex| regex.is_match(value))
                .unwrap_or(false);
        }

        Self::compare_with(candidate, &operator.data, operator.sensitive)
    }

    fn operator_matches_network(
        operator: &RuleOperator,
        derived: &AttemptDerived,
        caches: &RuleMatchCaches,
    ) -> bool {
        Self::operator_matches_network_with_derived(
            operator,
            operator.operand == "source.network",
            &derived,
            caches,
        )
    }

    fn operator_matches_network_with_derived(
        operator: &RuleOperator,
        source: bool,
        derived: &AttemptDerived,
        caches: &RuleMatchCaches,
    ) -> bool {
        let ip = if source {
            match derived.src_addr {
                Some(ip) => ip,
                None => return false,
            }
        } else {
            match derived.dst_addr {
                Some(ip) => ip,
                None => return false,
            }
        };

        if let Some(specs) = caches.network_specs_compiled.get(operator.data.as_str()) {
            return specs
                .iter()
                .any(|(network_ip, prefix_len)| Self::prefix_match(&ip, network_ip, *prefix_len));
        }

        if let Some(alias_specs) = caches.network_aliases.get(operator.data.as_str()) {
            return alias_specs
                .iter()
                .any(|spec| Self::matches_network_spec(&ip, spec));
        }

        Self::matches_network_spec(&ip, &operator.data)
    }

    fn list_slot_for_path<'a>(
        caches: &'a RuleMatchCaches,
        list_path: &Path,
    ) -> Option<&'a ListPathSlotCache> {
        caches
            .list_slot_by_path
            .get(list_path)
            .and_then(|idx| caches.list_slots.get(*idx))
    }

    fn operator_matches_lists(
        operator: &RuleOperator,
        _attempt: &ConnectionAttempt,
        derived: &AttemptDerived,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let source_scope = Self::list_scope_is_source(operator);
        let ip_text = Self::list_candidate_ip_text(derived, source_scope);
        let ip_addr = Self::list_candidate_ip_addr(derived, source_scope);

        let operand = operator.operand.as_str();
        let list_path = Path::new(operator.data.as_str());
        if let Some(slot) = Self::list_slot_for_path(caches, list_path) {
            return match operand {
                "lists.domains" => {
                    let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty())
                    else {
                        return false;
                    };

                    let lowered_host;
                    if !operator.sensitive && Self::has_ascii_uppercase(host) {
                        lowered_host = host.to_ascii_lowercase();
                        host = lowered_host.as_str();
                    }

                    slot.domains.contains(host)
                        || slot.domain_wildcards.matches_host(host)
                        || slot.domain_globs.iter().any(|glob| glob.is_match(host))
                }
                "lists.domains_regexp" => {
                    let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty())
                    else {
                        return false;
                    };

                    let lowered_host;
                    if !operator.sensitive && Self::has_ascii_uppercase(host) {
                        lowered_host = host.to_ascii_lowercase();
                        host = lowered_host.as_str();
                    }

                    let regex_cache = if operator.sensitive {
                        slot.regex_sensitive.as_ref()
                    } else {
                        slot.regex_insensitive.as_ref()
                    };
                    regex_cache
                        .map(|cache| cache.matches(host))
                        .unwrap_or(false)
                }
                "lists.ips" => {
                    slot.trimmed_values.contains(ip_text)
                        || ip_addr
                            .filter(|_| slot.networks.has_entries())
                            .map(|ip| slot.networks.contains(ip))
                            .unwrap_or(false)
                }
                "lists.hash.md5" => {
                    let Some(hash) = process.process_hash_md5.as_deref() else {
                        return false;
                    };
                    slot.trimmed_values.contains(hash.trim())
                }
                "lists.nets" => {
                    if slot.trimmed_values.contains(ip_text) {
                        return true;
                    }

                    ip_addr
                        .filter(|_| slot.networks.has_entries())
                        .map(|ip| slot.networks.contains(ip))
                        .unwrap_or(false)
                }
                _ => false,
            };
        }

        match operand {
            "lists.domains" => {
                let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty())
                else {
                    return false;
                };

                let lowered_host;
                if !operator.sensitive && Self::has_ascii_uppercase(host) {
                    lowered_host = host.to_ascii_lowercase();
                    host = lowered_host.as_str();
                }

                if caches
                    .list_domains
                    .get(list_path)
                    .map(|set| set.contains(host))
                    .unwrap_or(false)
                {
                    return true;
                }

                if caches
                    .list_domain_wildcards
                    .get(list_path)
                    .map(|trie| trie.matches_host(host))
                    .unwrap_or(false)
                {
                    return true;
                }

                caches
                    .list_domain_globs
                    .get(list_path)
                    .map(|globs| globs.iter().any(|glob| glob.is_match(host)))
                    .unwrap_or(false)
            }
            "lists.domains_regexp" => {
                let Some(mut host) = dst_host.map(str::trim).filter(|value| !value.is_empty())
                else {
                    return false;
                };

                let lowered_host;
                if !operator.sensitive && Self::has_ascii_uppercase(host) {
                    lowered_host = host.to_ascii_lowercase();
                    host = lowered_host.as_str();
                }

                let fast_map = if operator.sensitive {
                    &caches.list_regexes_sensitive_fast
                } else {
                    &caches.list_regexes_insensitive_fast
                };
                fast_map
                    .get(list_path)
                    .map(|cache| cache.matches(host))
                    .or_else(|| {
                        caches
                            .list_regexes
                            .get(&ListRegexCacheKey::new(list_path, operator.sensitive))
                            .map(|cache| cache.matches(host))
                    })
                    .unwrap_or(false)
            }
            "lists.ips" => {
                caches
                    .list_trimmed_values
                    .get(list_path)
                    .map(|set| set.contains(ip_text))
                    .unwrap_or(false)
                    || ip_addr
                        .and_then(|ip| {
                            caches
                                .list_networks
                                .get(list_path)
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
                    .get(list_path)
                    .map(|set| set.contains(hash.trim()))
                    .unwrap_or(false)
            }
            "lists.nets" => {
                if caches
                    .list_trimmed_values
                    .get(list_path)
                    .map(|set| set.contains(ip_text))
                    .unwrap_or(false)
                {
                    return true;
                }

                ip_addr
                    .and_then(|ip| {
                        caches
                            .list_networks
                            .get(list_path)
                            .filter(|index| index.has_entries())
                            .map(|index| index.contains(ip))
                    })
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    fn matches_range_spec(value: &str, range: &str) -> bool {
        let value = match value.trim().parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let Some((min, max)) = Self::parse_range_bounds(range) else {
            return false;
        };
        value >= min && value <= max
    }

    fn parse_range_bounds(range: &str) -> Option<(u64, u64)> {
        let (min_raw, max_raw) = range.split_once('-')?;
        let min = min_raw.trim().parse::<u64>().ok()?;
        let max = max_raw.trim().parse::<u64>().ok()?;
        Some((min, max))
    }

    fn operator_numeric_value(
        operand: &str,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
    ) -> Option<u64> {
        match operand {
            "process.id" => Some(u64::from(process.pid)),
            "user.id" => Some(u64::from(attempt.uid)),
            "dest.port" => Some(u64::from(attempt.dst_port)),
            "source.port" => Some(u64::from(attempt.src_port)),
            _ => None,
        }
    }

    fn env_preview_get<'a>(process: &'a ProcessInfo, key: &str) -> Option<&'a str> {
        if let Some(value) = process.env_map.get(key) {
            return Some(value.as_str());
        }
        process.env_preview.iter().find_map(|item| {
            let (name, value) = item.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    fn compare_with(candidate: &str, expected: &str, sensitive: bool) -> bool {
        if sensitive {
            candidate == expected
        } else {
            candidate.eq_ignore_ascii_case(expected)
        }
    }

    fn has_ascii_uppercase(value: &str) -> bool {
        value.bytes().any(|byte| byte.is_ascii_uppercase())
    }

    fn matches_joined_args(args: &[String], expected: &str, sensitive: bool) -> bool {
        if args.is_empty() {
            return expected.is_empty();
        }

        let expected_bytes = expected.as_bytes();
        let mut cursor = 0usize;

        for (idx, arg) in args.iter().enumerate() {
            if idx > 0 {
                if cursor >= expected_bytes.len() || expected_bytes[cursor] != b' ' {
                    return false;
                }
                cursor += 1;
            }

            let arg_bytes = arg.as_bytes();
            if cursor + arg_bytes.len() > expected_bytes.len() {
                return false;
            }

            let segment = &expected_bytes[cursor..cursor + arg_bytes.len()];
            let matches = if sensitive {
                segment == arg_bytes
            } else {
                segment.eq_ignore_ascii_case(arg_bytes)
            };
            if !matches {
                return false;
            }
            cursor += arg_bytes.len();
        }

        cursor == expected_bytes.len()
    }

    fn matches_network_spec(ip: &IpAddr, spec: &str) -> bool {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return false;
        }

        let (network_ip, prefix_len) = match RuleService::parse_network_spec(trimmed) {
            Some(value) => value,
            None => return false,
        };

        Self::prefix_match(ip, &network_ip, prefix_len)
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

    fn prefix_match(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
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

        match (ip, network) {
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
    async fn build_and_publish_snapshot(
        &self,
        rules_path: Arc<PathBuf>,
        rules: Vec<RuleRecord>,
    ) -> Result<usize> {
        let count = rules.len();
        let caches = Self::build_match_caches(&rules).await?;
        let active_rules = rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                let decision = RuleMatchDecision::from_rule(rule.action, rule.nolog);
                ActiveRuleCompiled {
                    name: rule.name.clone(),
                    operator: rule.operator.clone(),
                    terminal_on_match: rule.precedence || !decision.allow,
                    decision,
                    dispatch: Self::compile_active_operator_dispatch(&rule.operator, &caches),
                }
            })
            .collect();
        let mut attempt_text_needs = AttemptTextNeeds::default();
        for rule in rules.iter().filter(|rule| rule.enabled) {
            Self::collect_attempt_text_needs(&rule.operator, &mut attempt_text_needs);
        }
        let proto_rules = Arc::new(rules.iter().map(RuleRecord::to_proto).collect());
        self.publish_snapshot(RuleSnapshot {
            rules_path,
            rules,
            active_rules,
            attempt_text_needs,
            proto_rules,
            caches,
        });
        Ok(count)
    }

    pub async fn load_path<P>(&self, path: P) -> Result<usize>
    where
        P: AsRef<Path>,
    {
        let _update_guard = self.update_lock.lock().await;
        let path = Arc::new(path.as_ref().to_path_buf());
        let (loaded, temporary_rules) = Self::load_rules_from_path(path.as_ref()).await?;
        let loaded_count = self.build_and_publish_snapshot(path, loaded).await?;

        for (rule_name, duration) in temporary_rules {
            self.schedule_temporary_rule(rule_name, duration);
        }

        Ok(loaded_count)
    }

    pub async fn reload(&self) -> Result<usize> {
        let snapshot = self.snapshot();
        self.load_path(snapshot.rules_path.as_path()).await
    }

    pub async fn rules_path_arc(&self) -> Arc<PathBuf> {
        self.snapshot().rules_path.clone()
    }

    #[cfg(test)]
    pub async fn list_proto(&self) -> Vec<pb::Rule> {
        self.snapshot().proto_rules.as_ref().clone()
    }

    pub async fn list_proto_arc(&self) -> Arc<Vec<pb::Rule>> {
        self.snapshot().proto_rules.clone()
    }

    pub fn rules_count(&self) -> usize {
        self.snapshot().rules.len()
    }

    fn match_attempt_with_rule_name_in_snapshot(
        snapshot: &RuleSnapshot,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<(RuleMatchDecision, String)>> {
        let mut decision = None::<(RuleMatchDecision, &str)>;
        let derived = AttemptDerived::from_attempt(attempt);
        derived.prewarm(snapshot.attempt_text_needs);

        for rule in snapshot.active_rules.iter() {
            if !Self::operator_matches_compiled_rule(
                rule,
                attempt,
                &derived,
                process,
                dst_host,
                &snapshot.caches,
            ) {
                continue;
            }

            if rule.terminal_on_match {
                return Ok(Some((rule.decision, rule.name.clone())));
            }
            decision = Some((rule.decision, rule.name.as_str()));
        }

        Ok(decision.map(|(matched, name)| (matched, name.to_string())))
    }

    pub fn match_attempt_with_rule_name_sync(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<(RuleMatchDecision, String)>> {
        let snapshot = self.snapshot();
        Self::match_attempt_with_rule_name_in_snapshot(
            snapshot.as_ref(),
            attempt,
            process,
            dst_host,
        )
    }

    #[cfg(test)]
    pub async fn match_attempt(
        &self,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> Result<Option<RuleMatchDecision>> {
        Ok(self
            .match_attempt_with_rule_name_sync(attempt, process, dst_host)?
            .map(|(decision, _)| decision))
    }

    pub async fn upsert_from_proto(&self, rule: &pb::Rule) -> Result<RuleMatchDecision> {
        let mut record = RuleRecord::from_proto(rule);
        let now = RuleRecord::now_timestamp();
        if record.created_at.is_none() {
            record.created_at = Some(now);
        }
        record.updated_at = Some(now);

        if record.enabled {
            Self::validate_operator(&record.operator)?;
        }

        let decision = RuleMatchDecision::from_rule(record.action, record.nolog);

        if record.duration == RuleDuration::Once {
            return Ok(decision);
        }

        self.upsert_record(record).await?;
        Ok(decision)
    }

    pub async fn delete_by_name(&self, rule_name: &str) -> Result<()> {
        let _update_guard = self.update_lock.lock().await;
        let current = self.snapshot();
        let mut next_rules = current.rules.clone();
        next_rules.retain(|rule| rule.name != rule_name);

        let path = current.rules_path.clone();
        let rule_name = rule_name.to_string();
        let file_path = path.as_path().join(format!("{rule_name}.json"));
        if let Err(err) = tokio::fs::remove_file(&file_path).await
            && err.kind() != ErrorKind::NotFound
        {
            return Err(err.into());
        }

        let _ = self.build_and_publish_snapshot(path, next_rules).await?;

        Ok(())
    }

    async fn upsert_record(&self, record: RuleRecord) -> Result<()> {
        let _update_guard = self.update_lock.lock().await;
        let current = self.snapshot();
        let mut old_persisted = false;
        let mut next_rules = current.rules.clone();
        if let Some(existing) = next_rules
            .iter_mut()
            .find(|current| current.name == record.name)
        {
            old_persisted = existing.duration.persists_to_disk();
            *existing = record.clone();
        } else {
            next_rules.push(record.clone());
            next_rules.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        }

        let path = current.rules_path.clone();
        let file_path = path.as_path().join(format!("{}.json", record.name));
        if old_persisted && !record.duration.persists_to_disk() {
            if let Err(err) = tokio::fs::remove_file(&file_path).await
                && err.kind() != ErrorKind::NotFound
            {
                return Err(err.into());
            }
        }

        if record.duration.persists_to_disk() {
            tokio::fs::create_dir_all(path.as_path()).await?;
            let raw = serde_json::to_string_pretty(&RuleFile::from(&record))?;
            tokio::fs::write(&file_path, raw).await?;
        }

        let _ = self.build_and_publish_snapshot(path, next_rules).await?;

        if record.enabled && record.duration.temporary_spec().is_some() {
            self.schedule_temporary_rule(record.name.clone(), record.duration.clone());
        }

        Ok(())
    }

    fn schedule_temporary_rule(&self, rule_name: String, duration: RuleDuration) {
        let Some(duration_spec) = duration.temporary_spec().map(ToOwned::to_owned) else {
            return;
        };
        let Some(timeout) = Self::parse_duration_spec(&duration_spec) else {
            warn!(rule = %rule_name, duration = %duration_spec, "invalid temporary rule duration; skipping expiry scheduling");
            return;
        };

        let service = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;

            let _update_guard = service.update_lock.lock().await;
            let current = service.snapshot();
            let mut next_rules = current.rules.clone();
            let Some(idx) = next_rules.iter().position(|item| item.name == rule_name) else {
                return;
            };

            let current_rule = &next_rules[idx];
            if !current_rule.enabled {
                return;
            }
            if current_rule.duration.temporary_spec() != Some(duration_spec.as_str()) {
                return;
            }

            debug!(rule = %rule_name, duration = %duration_spec, "temporary rule expired");
            next_rules.remove(idx);

            let rules_path = current.rules_path.clone();
            match service
                .build_and_publish_snapshot(rules_path, next_rules)
                .await
            {
                Ok(_) => {}
                Err(err) => {
                    warn!(rule = %rule_name, err = %err, "failed to refresh rule match caches after expiry");
                }
            }
        });
    }
}

impl RuleService {
    async fn build_match_caches(rules: &[RuleRecord]) -> Result<RuleMatchCaches> {
        let mut list_path_needs = HashMap::new();
        let mut regex_keys = HashSet::new();
        let mut needs_network_aliases = false;
        let mut operator_needs = OperatorNeeds::default();

        for rule in rules.iter().filter(|rule| rule.enabled) {
            Self::collect_operator_dependencies(
                &rule.operator,
                &mut list_path_needs,
                &mut regex_keys,
                &mut needs_network_aliases,
                &mut operator_needs,
            );
        }

        let mut caches = RuleMatchCaches::default();

        for (path, needs) in list_path_needs {
            let slot_idx = caches.list_slots.len();
            caches.list_slot_by_path.insert(path.clone(), slot_idx);
            caches.list_slots.push(ListPathSlotCache::default());

            let needs_text_entries = needs.domains
                || needs.trimmed_values
                || needs.networks
                || !needs.regex_sensitivities.is_empty();
            let entries = if needs_text_entries {
                Some(Self::load_list_entries_async(&path).await?)
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
                        let host = RuleService::normalize_domain_list_entry(entry)?;
                        if let Some(suffix) = RuleService::wildcard_suffix(&host) {
                            wildcard_trie.insert_suffix(suffix);
                            return None;
                        }
                        if RuleService::is_domain_glob_pattern(&host) {
                            if let Ok(glob) = Glob::new(&host) {
                                glob_matchers.push(glob.compile_matcher());
                            }
                            return None;
                        }
                        Some(host)
                    })
                    .collect::<HashSet<_>>();
                let slot = &mut caches.list_slots[slot_idx];
                slot.domains = domains;
                slot.domain_wildcards = wildcard_trie;
                slot.domain_globs = glob_matchers;
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
                caches.list_slots[slot_idx].trimmed_values = trimmed_values;
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
                    .filter_map(RuleService::parse_network_spec)
                {
                    index.insert(network, prefix);
                }
                caches.list_slots[slot_idx].networks = index;
            }

            for sensitive in needs.regex_sensitivities {
                let cache = RuleService::build_list_regex_cache(
                    entries
                        .as_ref()
                        .expect("entries loaded when regex cache is required")
                        .iter(),
                    sensitive,
                );
                if sensitive {
                    caches.list_slots[slot_idx].regex_sensitive = Some(cache);
                } else {
                    caches.list_slots[slot_idx].regex_insensitive = Some(cache);
                }
            }
        }

        for key in regex_keys {
            if let Some(regex) = RuleService::compile_regex(&key.pattern, key.sensitive) {
                if key.sensitive {
                    caches
                        .regexes_sensitive_fast
                        .insert(key.pattern.clone(), regex.clone());
                } else {
                    caches
                        .regexes_insensitive_fast
                        .insert(key.pattern.clone(), regex.clone());
                }
                caches.regexes.insert(key, regex);
            }
        }

        for user_name in operator_needs.user_name_values {
            let uid = nix::unistd::User::from_name(user_name.as_str())
                .ok()
                .flatten()
                .map(|user| user.uid.as_raw());
            caches.user_name_uid.insert(user_name, uid);
        }

        for range in operator_needs.range_values {
            let bounds = Self::parse_range_bounds(&range);
            caches.range_bounds.insert(range, bounds);
        }

        if needs_network_aliases {
            caches.network_aliases = Self::load_network_aliases_map().await;
        }

        for network_value in operator_needs.network_values {
            let specs =
                if let Some(alias_specs) = caches.network_aliases.get(network_value.as_str()) {
                    alias_specs
                        .iter()
                        .filter_map(|entry| Self::parse_network_spec(entry))
                        .collect::<Vec<_>>()
                } else {
                    Self::parse_network_spec(&network_value)
                        .into_iter()
                        .collect::<Vec<_>>()
                };
            caches.network_specs_compiled.insert(network_value, specs);
        }

        Ok(caches)
    }

    fn collect_operator_dependencies(
        operator: &RuleOperator,
        list_path_needs: &mut HashMap<PathBuf, ListPathNeeds>,
        regex_keys: &mut HashSet<RegexCacheKey>,
        needs_network_aliases: &mut bool,
        operator_needs: &mut OperatorNeeds,
    ) {
        if operator.type_name.eq_ignore_ascii_case("regexp") {
            regex_keys.insert(RegexCacheKey::new(&operator.data, operator.sensitive));
        }

        if operator.type_name.eq_ignore_ascii_case("lists")
            || operator.operand.starts_with("lists.")
        {
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
            operator_needs.network_values.insert(operator.data.clone());
        }

        if operator.type_name.eq_ignore_ascii_case("simple") && operator.operand == "user.name" {
            operator_needs
                .user_name_values
                .insert(operator.data.clone());
        }

        if operator.type_name.eq_ignore_ascii_case("range") {
            operator_needs.range_values.insert(operator.data.clone());
        }

        for item in &operator.list {
            Self::collect_operator_dependencies(
                item,
                list_path_needs,
                regex_keys,
                needs_network_aliases,
                operator_needs,
            );
        }
    }
}

impl ListRegexCache {
    pub(crate) fn matches(&self, candidate: &str) -> bool {
        if self.aho_regexes.is_empty() && self.fallback_regexes.is_empty() {
            return false;
        }

        if let Some(aho) = &self.aho {
            let regex_count = self.aho_regexes.len();
            let mut tested_stack = [0_u64; 4];
            let mut tested_heap;
            let tested_words: &mut [u64] = if regex_count <= tested_stack.len() * 64 {
                &mut tested_stack
            } else {
                tested_heap = vec![0_u64; regex_count.div_ceil(64)];
                tested_heap.as_mut_slice()
            };
            for mat in aho.find_iter(candidate) {
                let idx = mat.pattern().as_usize();
                if let Some(indices) = self.aho_pattern_to_regex_indices.get(idx) {
                    for regex_idx in indices {
                        let word = *regex_idx / 64;
                        let bit = *regex_idx % 64;
                        let mask = 1_u64 << bit;
                        if (tested_words[word] & mask) != 0 {
                            continue;
                        }
                        tested_words[word] |= mask;
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

impl RuleService {
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
            if let Some(regex) = RuleService::compile_regex(entry, true) {
                total_regex_count += 1;
                if let Some(literal) = RuleService::extract_regex_literal_hint(entry, sensitive)
                    && RuleService::is_aho_friendly_regex_pattern(entry)
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

        let should_enable_aho = RuleService::should_enable_aho(
            total_regex_count,
            literal_hint_count,
            literal_total_len,
        );

        let (aho, aho_pattern_to_regex_indices) =
            if !should_enable_aho || literal_to_indices.is_empty() {
                fallback_regexes.extend(aho_regexes);
                aho_regexes = Vec::new();
                (None, Vec::new())
            } else {
                let mut literals = literal_to_indices.keys().collect::<Vec<_>>();
                literals.sort_unstable();

                let mut mapping = Vec::with_capacity(literals.len());
                for literal in &literals {
                    mapping.push(
                        literal_to_indices
                            .get(literal.as_str())
                            .cloned()
                            .unwrap_or_default(),
                    );
                }

                let aho = AhoCorasick::new(literals.iter().map(|literal| literal.as_str())).ok();
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
        if RuleService::wildcard_suffix(host).is_some() {
            return false;
        }

        host.contains('?') || host.contains('[') || host.contains(']') || host.contains('*')
    }

    fn compile_regex(pattern: &str, sensitive: bool) -> Option<Regex> {
        Regex::new(&RuleService::build_regex_pattern(pattern, sensitive)).ok()
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
                && let Err(err) = Self::validate_operator(&record.operator)
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
            && RuleService::compile_regex(&operator.data, operator.sensitive).is_none()
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

            if let Some(scope) = operator.scope.as_deref().map(str::trim)
                && !scope.is_empty()
            {
                let valid_scope =
                    scope.eq_ignore_ascii_case("src") || scope.eq_ignore_ascii_case("dst");
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

        if operator.type_name.eq_ignore_ascii_case("list")
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

    fn parse_duration_spec(raw: &str) -> Option<Duration> {
        let value = raw.trim().to_ascii_lowercase();
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

    async fn load_list_entries_async(path: &Path) -> Result<Vec<String>> {
        Self::load_list_entries_async_plain(path).await
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum ListsDomainsRegexpCacheMode {
    AhoAndCompiled,
    CompiledOnly,
}

impl RuleService {
    #[cfg(test)]
    fn bench_measure_lists_indexing_latency(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        regexp_mode: ListsDomainsRegexpCacheMode,
    ) -> Result<Duration> {
        let start = std::time::Instant::now();
        let _ = Self::bench_build_lists_match_caches(operand, entries, sensitive, regexp_mode)?;
        Ok(start.elapsed())
    }

    #[cfg(test)]
    fn bench_measure_lists_matching_latency(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        candidate_ip: &str,
        candidate_host: Option<&str>,
        iterations: usize,
        regexp_mode: ListsDomainsRegexpCacheMode,
    ) -> Result<(Duration, usize)> {
        let list_path = PathBuf::from("/__lists_bench_path__");
        let caches =
            Self::bench_build_lists_match_caches(operand, entries, sensitive, regexp_mode)?;

        let operator = RuleOperator {
            type_name: "lists".to_string(),
            operand: operand.to_string(),
            data: list_path.display().to_string(),
            sensitive,
            scope: None,
            list: Vec::new(),
        };

        let attempt = ConnectionAttempt {
            request_id: 1,
            protocol: crate::models::connection_state::TransportProtocol::Tcp,
            src_addr: "127.0.0.1".parse().expect("valid ip"),
            src_port: 10000,
            dst_addr: candidate_ip.parse().expect("valid ip"),
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
            env_map: std::collections::HashMap::new(),
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
        let derived = AttemptDerived::from_attempt(&attempt);
        for _ in 0..iterations {
            if RuleService::operator_matches_lists(
                &operator,
                &attempt,
                &derived,
                &process,
                candidate_host,
                &caches,
            ) {
                hits += 1;
            }
        }

        Ok((start.elapsed(), hits))
    }

    #[cfg(test)]
    fn bench_build_lists_match_caches(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        regexp_mode: ListsDomainsRegexpCacheMode,
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
                        let host = RuleService::normalize_domain_list_entry(entry)?;
                        if let Some(suffix) = RuleService::wildcard_suffix(&host) {
                            wildcard_trie.insert_suffix(suffix);
                            return None;
                        }
                        if RuleService::is_domain_glob_pattern(&host) {
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
                    .filter_map(|entry| RuleService::parse_network_spec(entry))
                {
                    index.insert(network, prefix);
                }
                caches.list_networks.insert(list_path.clone(), index);
            }
            "lists.domains_regexp" => {
                let cache = match regexp_mode {
                    ListsDomainsRegexpCacheMode::AhoAndCompiled => {
                        RuleService::build_list_regex_cache(normalized_entries.iter(), sensitive)
                    }
                    ListsDomainsRegexpCacheMode::CompiledOnly => {
                        RuleService::build_list_regex_cache_compiled_only(normalized_entries.iter())
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
}

impl RuleService {
    #[cfg(test)]
    fn build_list_regex_cache_compiled_only<'a>(
        entries: impl Iterator<Item = &'a String>,
    ) -> ListRegexCache {
        let mut fallback_regexes = Vec::new();
        for entry in entries {
            if let Some(regex) = Self::compile_regex(entry, true) {
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
            let file_entries = Self::parse_list_lines(raw.lines());

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
        let Some(path) = Self::resolve_network_aliases_path() else {
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
            scope: operator.scope.and_then(|scope| {
                if scope.trim().is_empty() {
                    None
                } else {
                    Some(scope)
                }
            }),
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
            scope: operator.scope.clone(),
            list: operator.list.iter().map(RuleFileOperator::from).collect(),
        }
    }
}

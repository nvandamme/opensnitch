use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
};

use aho_corasick::AhoCorasick;
use globset::GlobMatcher;
use regex::Regex;

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
            // Normalise to lower-case: trie lookups are case-insensitive
            // regardless of capitalisation in the source list file.
            node = node.children.entry(label.to_lowercase()).or_default();
        }

        let required = labels.len() + 1;
        node.min_host_labels_required = Some(
            node.min_host_labels_required
                .map(|current| current.min(required))
                .unwrap_or(required),
        );
    }

    pub(crate) fn matches_host(&self, host: &str) -> bool {
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

    pub(crate) fn has_entries(&self) -> bool {
        self.has_entries
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
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

use std::{collections::HashSet, path::PathBuf, time::Duration};

use anyhow::Result;
use globset::Glob;

use crate::{
    models::{
        connection_state::{ConnectionAttempt, TransportProtocol},
        process_state::{ProcessInfo, ProcessNode},
        rule_record::RuleOperator,
    },
    services::rule::rule_probe_support::ListsDomainsRegexpCacheMode,
    services::rule::{
        CidrTrieIndex, DomainWildcardTrie, ListRegexCache, ListRegexCacheKey, RuleMatchCaches,
        RuleService,
    },
};

impl RuleService {
    fn path_string(path: &std::path::Path) -> String {
        path.to_string_lossy().to_string()
    }

    pub(crate) fn bench_measure_lists_indexing_latency(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        regexp_mode: ListsDomainsRegexpCacheMode,
    ) -> Result<Duration> {
        let start = std::time::Instant::now();
        let _ = Self::bench_build_lists_match_caches(operand, entries, sensitive, regexp_mode)?;
        Ok(start.elapsed())
    }

    pub(crate) fn bench_measure_lists_matching_latency(
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
            data: Self::path_string(&list_path),
            sensitive,
            scope: None,
            list: Vec::new(),
        };

        let attempt = ConnectionAttempt {
            request_id: 1,
            protocol: TransportProtocol::Tcp,
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
            parent_chain: vec![ProcessNode {
                pid: 0,
                path: "/sbin/init".to_string(),
            }],
        };

        let start = std::time::Instant::now();
        let mut hits = 0usize;
        for _ in 0..iterations {
            if RuleService::bench_operator_matches_lists(
                &operator,
                &attempt,
                &process,
                candidate_host,
                &caches,
            ) {
                hits += 1;
            }
        }

        Ok((start.elapsed(), hits))
    }

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
                        let host = RuleService::bench_normalize_domain_list_entry(entry)?;
                        if let Some(suffix) = RuleService::bench_wildcard_suffix(&host) {
                            wildcard_trie.insert_suffix(suffix);
                            return None;
                        }
                        if RuleService::bench_is_domain_glob_pattern(&host) {
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
                        RuleService::bench_build_list_regex_cache(
                            normalized_entries.iter(),
                            sensitive,
                        )
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

    fn build_list_regex_cache_compiled_only<'a>(
        entries: impl Iterator<Item = &'a String>,
    ) -> ListRegexCache {
        let mut fallback_regexes = Vec::new();
        for entry in entries {
            if let Some(regex) = Self::bench_compile_regex(entry, true) {
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
}

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::Result;
use globset::Glob;
use tokio::task::JoinSet;

use crate::models::rule::record::{RuleOperator, RuleRecord};
use crate::utils::string_iter::trimmed_non_empty;

use super::{
    CidrTrieIndex, DomainWildcardTrie, ListPathSlotCache, RegexCacheKey, RuleMatchCaches,
    RuleService,
};

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

impl RuleService {
    pub(super) async fn build_match_caches(
        rules: &[RuleRecord],
        network_aliases_path: &Path,
    ) -> Result<RuleMatchCaches> {
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

        // Phase 1: load all list files in parallel — each path is read concurrently
        // via a JoinSet, eliminating serial I/O on the cold (cache-build) path.
        let mut load_tasks: JoinSet<Result<(PathBuf, ListPathNeeds, Option<Vec<String>>)>> =
            JoinSet::new();
        for (path, needs) in list_path_needs {
            let needs_text_entries = needs.domains
                || needs.trimmed_values
                || needs.networks
                || !needs.regex_sensitivities.is_empty();
            load_tasks.spawn(async move {
                let entries = if needs_text_entries {
                    Some(Self::load_list_entries_async_plain(&path).await?)
                } else {
                    None
                };
                Ok((path, needs, entries))
            });
        }

        // Phase 2: collect parallel results, then build per-slot caches serially.
        // Serial processing preserves deterministic slot-index assignment while all
        // file I/O has already completed concurrently in phase 1.
        let mut loaded: Vec<(PathBuf, ListPathNeeds, Option<Vec<String>>)> = Vec::new();
        while let Some(result) = load_tasks.join_next().await {
            loaded.push(result.map_err(|e| anyhow::anyhow!("list load task join: {e}"))??);
        }

        for (path, needs, entries) in loaded {
            let slot_idx = caches.list_slots.len();
            caches.list_slot_by_path.insert(path.clone(), slot_idx);
            caches.list_slots.push(ListPathSlotCache::default());

            if needs.domains {
                let mut wildcard_trie = DomainWildcardTrie::default();
                let mut glob_matchers = Vec::new();
                let domains = entries
                    .as_ref()
                    .expect("entries loaded when domains are required")
                    .iter()
                    .filter_map(|entry| {
                        let host = RuleService::normalize_domain_list_entry(entry)?;
                        // AdBlock/AdGuard ||domain^ anchor: must block the domain AND
                        // all its subdomains (per spec).  Use insert_domain_and_subdomains
                        // (required = labels.len()) so both example.org and www.example.org
                        // match; no separate exact-HashSet entry is needed.
                        if RuleService::is_adblock_domain_anchor(entry) {
                            wildcard_trie.insert_domain_and_subdomains(&host);
                            return None;
                        }
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

                // Cascaded regex sub-cache: extract `/pattern/` lines from the same
                // file and build a dedicated ListRegexCache (always case-insensitive —
                // DNS is case-insensitive per RFC 4343).  This allows a single
                // `lists.domains` operator to handle mixed files that contain both
                // plain/AdBlock domain entries and AdBlock-style regex network rules,
                // mirroring AdGuard's urlfilter unified engine approach.
                // The regex path is reached only when all fast-path lookups miss.
                let regex_patterns = entries
                    .as_ref()
                    .expect("entries loaded when domains are required")
                    .iter()
                    .filter_map(|entry| RuleService::extract_domain_list_regex_pattern(entry))
                    .collect::<Vec<_>>();
                if !regex_patterns.is_empty() {
                    caches.list_slots[slot_idx].domains_regex = Some(
                        RuleService::build_list_regex_cache(regex_patterns.iter(), false),
                    );
                }
            }

            if needs.trimmed_values {
                let trimmed_values = trimmed_non_empty(
                    entries
                        .as_ref()
                        .expect("entries loaded when trimmed_values are required")
                        .iter()
                        .map(String::as_str),
                )
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>();
                caches.list_slots[slot_idx].trimmed_values = trimmed_values;
            }

            if needs.networks {
                let mut index = CidrTrieIndex::default();
                for (network, prefix) in trimmed_non_empty(
                    entries
                        .as_ref()
                        .expect("entries loaded when networks are required")
                        .iter()
                        .map(String::as_str),
                )
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
            caches.network_aliases = Self::load_network_aliases_map(network_aliases_path).await;
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
        if Self::operator_type_is(operator.type_name.as_str(), "regexp") {
            regex_keys.insert(RegexCacheKey::new(&operator.data, operator.sensitive));
        }

        if Self::operator_is_lists(operator.type_name.as_str(), operator.operand.as_str()) {
            let path = PathBuf::from(operator.data.as_str());
            let needs = list_path_needs.entry(path).or_default();
            match operator.operand.as_str() {
                "lists.domains" => needs.domains = true,
                "lists.ips" | "lists.nets" => {
                    needs.trimmed_values = true;
                    needs.networks = true;
                }
                "lists.hash.md5" => needs.trimmed_values = true,
                "lists.domains_regexp" => {
                    needs.regex_sensitivities.insert(operator.sensitive);
                }
                _ => {}
            }
        }

        if Self::operator_type_is(operator.type_name.as_str(), "network") {
            *needs_network_aliases = true;
            operator_needs.network_values.insert(operator.data.clone());
        }

        if Self::operator_type_is(operator.type_name.as_str(), "simple")
            && operator.operand == "user.name"
        {
            operator_needs
                .user_name_values
                .insert(operator.data.clone());
        }

        if Self::operator_type_is(operator.type_name.as_str(), "range") {
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

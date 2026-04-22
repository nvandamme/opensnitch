use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use regex::Regex;

use crate::{
    models::{
        connection_state::ConnectionAttempt, process_state::ProcessInfo, rule_record::RuleOperator,
    },
    services::rule::{ListRegexCache, RuleMatchCaches, RuleService},
};

#[derive(Clone, Copy)]
pub(crate) enum ListsDomainsRegexpCacheMode {
    AhoAndCompiled,
    CompiledOnly,
}

impl RuleService {
    pub(crate) fn probe_operator_matches_against(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        Self::operator_matches_against(operator, attempt, process, dst_host, caches)
    }

    pub(crate) fn probe_build_list_regex_cache<'a>(
        entries: impl Iterator<Item = &'a String>,
        sensitive: bool,
    ) -> ListRegexCache {
        RuleService::build_list_regex_cache(entries, sensitive)
    }

    pub(crate) fn probe_build_regex_pattern(pattern: &str, sensitive: bool) -> String {
        Self::build_regex_pattern(pattern, sensitive)
    }

    pub(crate) fn probe_validate_operator(operator: &RuleOperator) -> Result<()> {
        Self::validate_operator(operator)
    }

    pub(crate) async fn probe_load_list_entries_async_plain(path: &Path) -> Result<Vec<String>> {
        Self::load_list_entries_async_plain(path).await
    }

    pub(crate) fn probe_measure_lists_indexing_latency(
        operand: &str,
        entries: &[String],
        sensitive: bool,
        regexp_mode: ListsDomainsRegexpCacheMode,
    ) -> Result<Duration> {
        Self::bench_measure_lists_indexing_latency(operand, entries, sensitive, regexp_mode)
    }

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

    pub(crate) fn bench_operator_matches_lists(
        operator: &RuleOperator,
        attempt: &ConnectionAttempt,
        process: &ProcessInfo,
        dst_host: Option<&str>,
        caches: &RuleMatchCaches,
    ) -> bool {
        let derived = super::matching::AttemptDerived::from_attempt(attempt);
        Self::operator_matches_lists(operator, attempt, &derived, process, dst_host, caches)
    }

    pub(crate) fn bench_normalize_domain_list_entry(entry: &str) -> Option<String> {
        Self::normalize_domain_list_entry(entry)
    }

    pub(crate) fn bench_wildcard_suffix(host: &str) -> Option<&str> {
        Self::wildcard_suffix(host)
    }

    pub(crate) fn bench_is_domain_glob_pattern(host: &str) -> bool {
        Self::is_domain_glob_pattern(host)
    }

    pub(crate) fn bench_build_list_regex_cache<'a>(
        entries: impl Iterator<Item = &'a String>,
        sensitive: bool,
    ) -> ListRegexCache {
        Self::build_list_regex_cache(entries, sensitive)
    }

    pub(crate) fn bench_compile_regex(pattern: &str, sensitive: bool) -> Option<Regex> {
        Self::compile_regex(pattern, sensitive)
    }
}

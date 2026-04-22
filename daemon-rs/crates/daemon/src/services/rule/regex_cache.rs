use std::collections::HashMap;

use aho_corasick::AhoCorasick;

use super::{ListRegexCache, RuleService};

const AHO_MIN_REGEXES: usize = 128;
const AHO_MIN_LITERAL_COVERAGE: f64 = 0.6;
const AHO_MIN_AVG_LITERAL_LEN: f64 = 6.0;

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
    pub(super) fn build_list_regex_cache<'a>(
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
            literal.to_lowercase()
        })
    }
}

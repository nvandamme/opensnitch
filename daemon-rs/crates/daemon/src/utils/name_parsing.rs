pub(crate) fn case_folded(name: &str) -> String {
    name.to_lowercase()
}

pub fn normalized_name(name: &str) -> String {
    case_folded(name.trim())
}

pub(crate) fn sanitize_ascii_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub(crate) struct AliasRule<'a> {
    pub canonical: &'a str,
    pub exact: &'a [&'a str],
    pub prefixes: &'a [&'a str],
}

pub(crate) fn canonicalize_alias(raw: &str, rules: &[AliasRule<'_>]) -> String {
    let normalized = normalized_name(raw);

    for rule in rules {
        if rule.exact.contains(&normalized.as_str())
            || rule
                .prefixes
                .iter()
                .any(|prefix| normalized.starts_with(prefix))
        {
            return rule.canonical.to_string();
        }
    }

    normalized
}

pub(crate) fn suffix_after_any_prefix(raw: &str, prefixes: &[&str]) -> Option<String> {
    let trimmed = raw.trim();
    let lowered = trimmed.to_lowercase();

    for prefix in prefixes {
        if lowered.starts_with(prefix) {
            let suffix = trimmed.get(prefix.len()..).unwrap_or("").trim();
            if !suffix.is_empty() {
                return Some(suffix.to_string());
            }
        }
    }

    None
}

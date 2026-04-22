pub(crate) fn sample_content_lines_match<F>(sample: &[String], mut predicate: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    let mut content_lines = 0usize;
    let mut matching_lines = 0usize;

    for line in sample {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        content_lines += 1;
        if predicate(trimmed) {
            matching_lines += 1;
        }
    }

    content_lines == 0 || matching_lines > 0
}

fn sample_first_ascii_token_matches<F>(sample: &[String], mut predicate: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    sample_content_lines_match(sample, |trimmed| {
        let token = trimmed.split_ascii_whitespace().next().unwrap_or("");
        predicate(token)
    })
}

pub(crate) fn looks_like_ip_token(s: &str) -> bool {
    let has_digit_start = s.starts_with(|c: char| c.is_ascii_digit());
    let is_ipv6_like = !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    has_digit_start || is_ipv6_like
}

pub(crate) fn looks_like_domain_or_glob_token(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if !s.contains('.') {
        return false;
    }
    if s.starts_with('<') || s.starts_with('{') {
        return false;
    }
    if looks_like_ip_token(s) {
        return false;
    }

    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '?'))
}

pub(crate) fn is_hosts_file_like(sample: &[String]) -> bool {
    if sample.is_empty() {
        return true;
    }
    sample_first_ascii_token_matches(sample, looks_like_ip_token)
}

pub(crate) fn is_domains_list_like(sample: &[String]) -> bool {
    if sample.is_empty() {
        return true;
    }
    sample_first_ascii_token_matches(sample, looks_like_domain_or_glob_token)
}

pub(crate) fn is_ip_list_like(sample: &[String]) -> bool {
    sample_first_ascii_token_matches(sample, |token| {
        looks_like_ip_token(token) && !token.contains('/')
    })
}

pub(crate) fn is_nets_list_like(sample: &[String]) -> bool {
    sample_first_ascii_token_matches(sample, |token| {
        if let Some(slash) = token.find('/') {
            let ip_part = &token[..slash];
            let prefix = token[slash + 1..].trim();
            return looks_like_ip_token(ip_part) && !prefix.is_empty();
        }
        false
    })
}

pub(crate) fn is_domain_regexps_list_like(sample: &[String]) -> bool {
    sample_content_lines_match(sample, |trimmed| {
        !trimmed.starts_with('<') && !trimmed.starts_with('{')
    })
}

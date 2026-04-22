use anyhow::Result;

use super::SubscriptionRecord;
use super::defaults::{DEFAULT_INTERVAL_SECONDS, DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECONDS};
use crate::utils::list_shape::{
    is_domain_regexps_list_like, is_domains_list_like, is_hosts_file_like, is_ip_list_like,
    is_nets_list_like,
};
use crate::utils::name_parsing::{normalized_name, sanitize_ascii_name};
use crate::utils::stable_id::hex_id_from_pair;
use crate::utils::time_nonce::now_rfc3339_utc;

pub(super) fn is_known_format(format: &str) -> bool {
    matches!(
        normalize_format(format).as_str(),
        "hosts" | "domains" | "ips" | "nets" | "domain_regexps"
    )
}

pub(crate) fn validate_format_sample(format: &str, sample: &[String]) -> Result<(), String> {
    match normalize_format(format).as_str() {
        "hosts" => {
            if !is_hosts_file_like(sample) {
                return Err(
                    "downloaded file does not look like a valid hosts-format list \
                     (expected '0.0.0.0 hostname' or '127.0.0.1 hostname' lines)"
                        .to_string(),
                );
            }
        }
        "domains" => {
            if !is_domains_list_like(sample) {
                return Err("downloaded file does not look like a valid domains list \
                     (expected one domain/glob per line, e.g. 'ads.example.com' or '*.tracker.net')"
                    .to_string());
            }
        }
        "ips" => {
            if !is_ip_list_like(sample) {
                return Err("downloaded file does not look like a valid IP list \
                     (expected one IPv4 or IPv6 address per line)"
                    .to_string());
            }
        }
        "nets" => {
            if !is_nets_list_like(sample) {
                return Err("downloaded file does not look like a valid nets list \
                     (expected one CIDR block per line, e.g. '10.0.0.0/8')"
                    .to_string());
            }
        }
        "domain_regexps" => {
            if !is_domain_regexps_list_like(sample) {
                return Err(
                    "downloaded file does not look like a valid domain_regexps list \
                     (expected one regexp per line)"
                        .to_string(),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn normalize_format(format: &str) -> String {
    match normalized_name(format).as_str() {
        // Canonical format names — map to the rule-list operator they feed.
        //
        //   "hosts"          → lists.domains       (0.0.0.0/127.0.0.1 <hostname> lines)
        //   "domains"        → lists.domains       (plain <hostname>/glob per line;
        //                        uses the efficient trie+glob index, not AhoCorasick)
        //   "ips"            → lists.ips            (plain IPv4/IPv6 per line)
        //   "nets"           → lists.nets           (CIDR per line)
        //   "domain_regexps" → lists.domains_regexp (one regexp per line)
        "hosts" | "" => "hosts".to_string(),
        "domains" => "domains".to_string(),
        "ips" => "ips".to_string(),
        "nets" => "nets".to_string(),
        "domain_regexps" => "domain_regexps".to_string(),
        // Unknown formats preserved as-is so future formats survive round-trips.
        other => other.to_string(),
    }
}

pub(super) fn normalize_record(mut r: SubscriptionRecord) -> SubscriptionRecord {
    if r.id.is_empty() {
        r.id = hex_id_from_pair(&r.url, &r.name);
    }
    if r.format.is_empty() {
        r.format = "hosts".to_string();
    } else {
        r.format = normalize_format(&r.format);
    }
    if r.filename.is_empty() {
        r.filename = sanitize_ascii_name(if !r.name.is_empty() { &r.name } else { &r.id });
    }
    if r.name.is_empty() {
        r.name.clone_from(&r.filename);
    }
    if r.interval_seconds == 0 {
        r.interval_seconds = DEFAULT_INTERVAL_SECONDS;
    }
    if r.timeout_seconds == 0 {
        r.timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    }
    if r.max_bytes == 0 {
        r.max_bytes = DEFAULT_MAX_BYTES;
    }
    if r.status.is_empty() || r.status == "unspecified" {
        r.status = "pending".to_string();
    }
    if r.last_updated.is_empty() {
        r.last_updated = now_rfc3339_utc();
    }
    r
}

use globset::Glob;
use nix::unistd::{Uid, User};
use regex::Regex;

use crate::models::{
    connection_state::{ConnectionAttempt, TransportProtocol},
    process_state::{ProcessInfo, ProcessNode},
    rule_record::RuleOperator,
};
use crate::platform::netlink::ifaces::NetIfaceAdapter;
use crate::services::rule::{
    CidrTrieIndex, DomainWildcardTrie, ListRegexCache, ListRegexCacheKey, RegexCacheKey,
    RuleMatchCaches, RuleService,
};
use crate::tests::support::{TestDir, path_string};

fn loopback_ifindex() -> Option<u32> {
    NetIfaceAdapter::interface_name_map()
        .ok()?
        .into_iter()
        .find_map(|(ifindex, name)| (name == "lo").then_some(ifindex))
}

fn probe_process() -> ProcessInfo {
    ProcessInfo {
        pid: 4242,
        path: "/usr/bin/curl".to_string(),
        args: vec!["curl".to_string()],
        cwd: None,
        env_preview: Vec::new(),
        env_map: std::collections::HashMap::new(),
        process_hash: Some("hash-value".to_string()),
        process_hash_md5: Some("hash-value".to_string()),
        process_hash_sha1: Some("hash-value".to_string()),
        parent_chain: vec![ProcessNode {
            pid: 1,
            path: "/sbin/init".to_string(),
        }],
    }
}

fn probe_attempt(dst_ip: &str) -> ConnectionAttempt {
    ConnectionAttempt {
        request_id: 7,
        protocol: TransportProtocol::Tcp,
        src_addr: "127.0.0.1".parse().expect("valid ip"),
        src_port: 12345,
        dst_addr: dst_ip.parse().expect("valid ip"),
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
        Regex::new(&RuleService::probe_build_regex_pattern(
            &ins_key.pattern,
            false,
        ))
        .expect("compile insensitive regex"),
    );
    caches.regexes.insert(
        sen_key.clone(),
        Regex::new(&RuleService::probe_build_regex_pattern(
            &sen_key.pattern,
            true,
        ))
        .expect("compile sensitive regex"),
    );

    let insensitive = RuleOperator {
        type_name: "regexp".to_string(),
        operand: "dest.host".to_string(),
        data: "^example\\.org$".to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };
    let sensitive = RuleOperator {
        sensitive: true,
        ..insensitive.clone()
    };

    let attempt = probe_attempt("10.0.0.3");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
        &insensitive,
        &attempt,
        &process,
        Some("ExAmPlE.OrG"),
        &caches
    ));
    assert!(!RuleService::probe_operator_matches_against(
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
        Regex::new(&RuleService::probe_build_regex_pattern(
            &key.pattern,
            key.sensitive,
        ))
        .expect("compile go-style lowered regex"),
    );

    let op = RuleOperator {
        type_name: "regexp".to_string(),
        operand: "dest.host".to_string(),
        data: "^EXAMPLE\\.ORG$".to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &op,
        &probe_attempt("10.0.0.3"),
        &probe_process(),
        Some("ExAmPlE.OrG"),
        &caches,
    ));
}

#[test]
fn iface_in_operand_matches_interface_name() {
    let Some(lo_idx) = loopback_ifindex() else {
        return;
    };
    if lo_idx == 0 {
        return;
    }

    let mut attempt = probe_attempt("10.0.0.3");
    attempt.iface_in_idx = lo_idx;

    let op = RuleOperator {
        type_name: "simple".to_string(),
        operand: "iface.in".to_string(),
        data: "lo".to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &op,
        &attempt,
        &probe_process(),
        None,
        &RuleMatchCaches::default(),
    ));
}

#[test]
fn iface_out_operand_matches_interface_name() {
    let Some(lo_idx) = loopback_ifindex() else {
        return;
    };
    if lo_idx == 0 {
        return;
    }

    let mut attempt = probe_attempt("10.0.0.3");
    attempt.iface_out_idx = lo_idx;

    let op = RuleOperator {
        type_name: "simple".to_string(),
        operand: "iface.out".to_string(),
        data: "lo".to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &op,
        &attempt,
        &probe_process(),
        None,
        &RuleMatchCaches::default(),
    ));
}

#[test]
fn user_name_operand_matches_current_uid() {
    let Some(user) = User::from_uid(Uid::current()).ok().flatten() else {
        return;
    };

    let mut attempt = probe_attempt("10.0.0.3");
    attempt.uid = user.uid.as_raw();

    let op = RuleOperator {
        type_name: "simple".to_string(),
        operand: "user.name".to_string(),
        data: user.name,
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &op,
        &attempt,
        &probe_process(),
        None,
        &RuleMatchCaches::default(),
    ));
}

#[test]
fn lists_domain_and_domain_regexp_match_expected_host_values() {
    let dir = TestDir::new("rule-match-domains-list");
    let list_path = dir.path.join("domains.txt");
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
        data: path_string(&list_path),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };
    let domain_re_op = RuleOperator {
        operand: "lists.domains_regexp".to_string(),
        ..domain_op.clone()
    };

    let attempt = probe_attempt("10.0.0.4");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
        &domain_op,
        &attempt,
        &process,
        Some("example.org"),
        &caches
    ));
    assert!(RuleService::probe_operator_matches_against(
        &domain_re_op,
        &attempt,
        &process,
        Some("API.EXAMPLE.ORG"),
        &caches
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &domain_re_op,
        &attempt,
        &process,
        Some("other.example.org"),
        &caches
    ));
}

#[test]
fn lists_ips_and_nets_match_expected_destination() {
    let dir = TestDir::new("rule-match-ips-nets-list");
    let ips_path = dir.path.join("ips.txt");
    let nets_path = dir.path.join("nets.txt");

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
        data: path_string(&ips_path),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };
    let nets_op = RuleOperator {
        operand: "lists.nets".to_string(),
        data: path_string(&nets_path),
        ..ips_op.clone()
    };

    let attempt = probe_attempt("10.0.0.4");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
        &ips_op, &attempt, &process, None, &caches,
    ));
    assert!(RuleService::probe_operator_matches_against(
        &nets_op, &attempt, &process, None, &caches,
    ));
}

#[test]
fn lists_ips_scope_src_matches_source_address() {
    let dir = TestDir::new("rule-match-ips-src-scope-list");
    let ips_path = dir.path.join("ips.txt");
    let mut caches = RuleMatchCaches::default();
    caches.list_trimmed_values.insert(
        ips_path.clone(),
        ["127.0.0.1".to_string()].into_iter().collect(),
    );

    let src_scope_op = RuleOperator {
        type_name: "lists".to_string(),
        operand: "lists.ips".to_string(),
        data: path_string(&ips_path),
        sensitive: false,
        scope: Some("src".to_string()),
        list: Vec::new(),
    };
    let default_scope_op = RuleOperator {
        scope: None,
        ..src_scope_op.clone()
    };

    let attempt = probe_attempt("10.0.0.4");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
        &src_scope_op,
        &attempt,
        &process,
        None,
        &caches,
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &default_scope_op,
        &attempt,
        &process,
        None,
        &caches,
    ));
}

#[test]
fn lists_nets_matches_ipv6_prefixes() {
    let dir = TestDir::new("rule-match-nets-v6-list");
    let nets_path = dir.path.join("nets.txt");
    let mut caches = RuleMatchCaches::default();
    caches.list_networks.insert(nets_path.clone(), {
        let mut index = CidrTrieIndex::default();
        index.insert("2001:db8::".parse().expect("parse v6 test network ip"), 32);
        index
    });

    let nets_op = RuleOperator {
        type_name: "lists".to_string(),
        operand: "lists.nets".to_string(),
        data: path_string(&nets_path),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &nets_op,
        &probe_attempt("2001:db8::10"),
        &probe_process(),
        None,
        &caches,
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &nets_op,
        &probe_attempt("2001:dead::10"),
        &probe_process(),
        None,
        &caches,
    ));
}

#[test]
fn lists_domains_wildcard_fallback_matches_subdomains_only() {
    let dir = TestDir::new("rule-match-domains-wildcard-list");
    let list_path = dir.path.join("domains.txt");
    let mut caches = RuleMatchCaches::default();
    let mut trie = DomainWildcardTrie::default();
    trie.insert_suffix("example.org");
    caches.list_domain_wildcards.insert(list_path.clone(), trie);

    let wildcard_op = RuleOperator {
        type_name: "lists".to_string(),
        operand: "lists.domains".to_string(),
        data: path_string(&list_path),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &wildcard_op,
        &probe_attempt("10.0.0.4"),
        &probe_process(),
        Some("api.example.org"),
        &caches,
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &wildcard_op,
        &probe_attempt("10.0.0.4"),
        &probe_process(),
        Some("example.org"),
        &caches,
    ));
}

#[test]
fn lists_domains_glob_fallback_matches_extended_patterns() {
    let dir = TestDir::new("rule-match-domains-glob-list");
    let list_path = dir.path.join("domains.txt");
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
        data: path_string(&list_path),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &glob_op,
        &probe_attempt("10.0.0.4"),
        &probe_process(),
        Some("api-12.example.org"),
        &caches,
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &glob_op,
        &probe_attempt("10.0.0.4"),
        &probe_process(),
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

    let cache = RuleService::probe_build_list_regex_cache(entries.iter(), false);
    assert!(cache.aho.is_none());
    assert!(cache.aho_regexes.is_empty());
    assert!(!cache.fallback_regexes.is_empty());
}

#[test]
fn list_regex_cache_enables_aho_for_high_literal_coverage() {
    let entries = (0..256)
        .map(|i| format!("^host-{i}\\.example\\.org$"))
        .collect::<Vec<_>>();

    let cache = RuleService::probe_build_list_regex_cache(entries.iter(), false);
    assert!(cache.aho.is_some());
    assert!(!cache.aho_regexes.is_empty());
}

#[test]
fn list_regex_cache_keeps_complex_regex_fallback_when_aho_enabled() {
    let mut entries = (0..256)
        .map(|i| format!("^host-{i}\\.example\\.org$"))
        .collect::<Vec<_>>();
    entries.push("^(?:service|api)-[a-z0-9-]+\\.example\\.org$".to_string());

    let cache = RuleService::probe_build_list_regex_cache(entries.iter(), false);
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
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_operator_matches_against(
        &op,
        &probe_attempt("10.0.0.3"),
        &probe_process(),
        None,
        &RuleMatchCaches::default(),
    ));
}

#[test]
fn process_hash_operands_do_not_match_when_checksums_missing() {
    // Safety invariant: hash-based rules must NOT match while the hash is still being
    // computed in the background.  The verdict flow falls through to the configured
    // default action, which is the safe side.
    let mut process = probe_process();
    process.process_hash_md5 = None;
    process.process_hash_sha1 = None;

    let md5_op = RuleOperator {
        type_name: "simple".to_string(),
        operand: "process.hash.md5".to_string(),
        data: "anything".to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };
    let sha1_op = RuleOperator {
        operand: "process.hash.sha1".to_string(),
        ..md5_op.clone()
    };

    assert!(!RuleService::probe_operator_matches_against(
        &md5_op,
        &probe_attempt("10.0.0.3"),
        &process,
        None,
        &RuleMatchCaches::default(),
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &sha1_op,
        &probe_attempt("10.0.0.3"),
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
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_validate_operator(&op).is_ok());
}

#[test]
fn validate_operator_rejects_invalid_network_operand() {
    let op = RuleOperator {
        type_name: "network".to_string(),
        operand: "dest.host".to_string(),
        data: "10.0.0.0/8".to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };

    assert!(RuleService::probe_validate_operator(&op).is_err());
}

#[test]
fn simple_operands_match_expected_fields() {
    let attempt = probe_attempt("185.53.178.14");
    let process = probe_process();

    let process_id = RuleOperator {
        type_name: "simple".to_string(),
        operand: "process.id".to_string(),
        data: process.pid.to_string(),
        sensitive: false,
        scope: None,
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

    assert!(RuleService::probe_operator_matches_against(
        &process_id,
        &attempt,
        &process,
        Some("opensnitch.io"),
        &RuleMatchCaches::default(),
    ));
    assert!(RuleService::probe_operator_matches_against(
        &process_path,
        &attempt,
        &process,
        Some("opensnitch.io"),
        &RuleMatchCaches::default(),
    ));
    assert!(RuleService::probe_operator_matches_against(
        &process_cmd,
        &attempt,
        &process,
        Some("opensnitch.io"),
        &RuleMatchCaches::default(),
    ));
    assert!(RuleService::probe_operator_matches_against(
        &dst_ip,
        &attempt,
        &process,
        Some("opensnitch.io"),
        &RuleMatchCaches::default(),
    ));
    assert!(RuleService::probe_operator_matches_against(
        &user_id,
        &attempt,
        &process,
        Some("opensnitch.io"),
        &RuleMatchCaches::default(),
    ));
}

#[test]
fn source_operands_match_expected_fields() {
    let attempt = probe_attempt("10.0.0.3");
    let process = probe_process();

    let src_ip = RuleOperator {
        type_name: "simple".to_string(),
        operand: "source.ip".to_string(),
        data: attempt.src_addr.to_string(),
        sensitive: false,
        scope: None,
        list: Vec::new(),
    };
    let src_port = RuleOperator {
        operand: "source.port".to_string(),
        data: attempt.src_port.to_string(),
        ..src_ip.clone()
    };

    assert!(RuleService::probe_operator_matches_against(
        &src_ip,
        &attempt,
        &process,
        Some("opensnitch.io"),
        &RuleMatchCaches::default(),
    ));
    assert!(RuleService::probe_operator_matches_against(
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
        scope: None,
        list: Vec::new(),
    };

    assert!(!RuleService::probe_operator_matches_against(
        &op,
        &probe_attempt("10.0.0.3"),
        &probe_process(),
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
        Regex::new(&RuleService::probe_build_regex_pattern(
            &regex_key.pattern,
            true,
        ))
        .expect("compile empty-host regex"),
    );

    let simple_empty = RuleOperator {
        type_name: "simple".to_string(),
        operand: "dest.host".to_string(),
        data: String::new(),
        sensitive: true,
        scope: None,
        list: Vec::new(),
    };
    let regexp_empty = RuleOperator {
        type_name: "regexp".to_string(),
        operand: "dest.host".to_string(),
        data: "^$".to_string(),
        sensitive: true,
        scope: None,
        list: Vec::new(),
    };

    let attempt = probe_attempt("10.0.0.3");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
        &simple_empty,
        &attempt,
        &process,
        Some(""),
        &caches,
    ));
    assert!(RuleService::probe_operator_matches_against(
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
        scope: None,
        list: Vec::new(),
    };
    let miss_op = RuleOperator {
        data: "8.8.8.8/24".to_string(),
        ..match_op.clone()
    };

    let attempt = probe_attempt("185.53.178.14");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
        &match_op,
        &attempt,
        &process,
        None,
        &RuleMatchCaches::default(),
    ));
    assert!(!RuleService::probe_operator_matches_against(
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
        Regex::new(&RuleService::probe_build_regex_pattern(
            &regex_key.pattern,
            false,
        ))
        .expect("compile list child regex"),
    );

    let list_op = RuleOperator {
        type_name: "list".to_string(),
        operand: "list".to_string(),
        data: String::new(),
        sensitive: false,
        scope: None,
        list: vec![
            RuleOperator {
                type_name: "regexp".to_string(),
                operand: "process.path".to_string(),
                data: "^/usr/bin/.*".to_string(),
                sensitive: false,
                scope: None,
                list: Vec::new(),
            },
            RuleOperator {
                type_name: "simple".to_string(),
                operand: "dest.ip".to_string(),
                data: "185.53.178.14".to_string(),
                sensitive: false,
                scope: None,
                list: Vec::new(),
            },
            RuleOperator {
                type_name: "simple".to_string(),
                operand: "dest.port".to_string(),
                data: "443".to_string(),
                sensitive: false,
                scope: None,
                list: Vec::new(),
            },
        ],
    };

    let attempt = probe_attempt("185.53.178.14");
    let process = probe_process();

    assert!(RuleService::probe_operator_matches_against(
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
        scope: None,
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

    assert!(RuleService::probe_validate_operator(&invalid_desc).is_err());
    assert!(RuleService::probe_validate_operator(&invalid_open_min).is_err());
    assert!(RuleService::probe_validate_operator(&invalid_open_max).is_err());
    assert!(
        RuleService::probe_validate_operator(&RuleOperator {
            type_name: "range".to_string(),
            operand: "dest.port".to_string(),
            data: "1 - 5000".to_string(),
            sensitive: false,
            scope: None,
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
        scope: None,
        list: Vec::new(),
    };

    let process = probe_process();
    let mut in_attempt = probe_attempt("10.0.0.5");
    in_attempt.dst_port = 150;
    let mut out_attempt = probe_attempt("10.0.0.6");
    out_attempt.dst_port = 443;

    assert!(RuleService::probe_operator_matches_against(
        &range_op,
        &in_attempt,
        &process,
        None,
        &RuleMatchCaches::default()
    ));
    assert!(!RuleService::probe_operator_matches_against(
        &range_op,
        &out_attempt,
        &process,
        None,
        &RuleMatchCaches::default()
    ));
}

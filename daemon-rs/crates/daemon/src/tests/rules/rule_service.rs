use anyhow::Result;
use std::time::Instant;
use storage_format_core::StorageFormatCodec;
use storage_format_json::JsonStorageFormat;
use transport_wire_core::{WireRule, WireRuleOperator};

use crate::{
    models::{
        connection::state::{ConnectionAttempt, TransportProtocol},
        process::state::{ProcessInfo, ProcessNode},
        rule::storage::{RuleFile, RuleFileOperator},
    },
    services::rule::rule_probe_support::ListsDomainsRegexpCacheMode,
    services::rule::{RuleMatchDecision, RuleService},
    tests::support::{TestDir, path_string},
};

async fn upsert_rule(service: &RuleService, rule: WireRule) -> Result<RuleMatchDecision> {
    service.upsert_from_wire(&rule).await
}

fn probe_process() -> ProcessInfo {
    ProcessInfo {
        pid: 4242,
        path: "/usr/bin/curl".to_string(),
        comm: Some("curl".to_string()),
        root: "/".to_string(),
        uid: Some(1000),
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

fn probe_process_with_env() -> ProcessInfo {
    let mut process = probe_process();
    process.env_preview = vec!["FOO=bar".to_string(), "PATH=/usr/bin".to_string()];
    process.env_map.insert("FOO".to_string(), "bar".to_string());
    process
        .env_map
        .insert("PATH".to_string(), "/usr/bin".to_string());
    process
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

async fn write_rule_file(
    rules_dir: &std::path::Path,
    name: &str,
    action: &str,
    enabled: bool,
    precedence: bool,
    operator: RuleFileOperator,
) -> Result<()> {
    let rule = RuleFile {
        created: String::new(),
        updated: String::new(),
        name: name.to_string(),
        description: String::new(),
        action: action.to_string(),
        duration: "always".to_string(),
        enabled,
        precedence,
        nolog: false,
        operator,
    };

    tokio::fs::write(
        rules_dir.join(format!("{name}.json")),
        JsonStorageFormat.convert_to_storage(&rule)?,
    )
    .await?;

    Ok(())
}

async fn measure_lists_branch_matching(
    operand: &str,
    list_payload: &str,
    candidate_ip: &str,
    candidate_host: Option<&str>,
    iterations: usize,
) -> Result<(std::time::Duration, usize)> {
    let entries = parse_payload_entries(list_payload);
    let mode = if operand == "lists.domains_regexp" {
        ListsDomainsRegexpCacheMode::AhoAndCompiled
    } else {
        ListsDomainsRegexpCacheMode::CompiledOnly
    };
    RuleService::probe_measure_lists_matching_latency(
        operand,
        &entries,
        false,
        candidate_ip,
        candidate_host,
        iterations,
        mode,
    )
}

async fn measure_segment_file_load_median_latency(
    segment_paths: &[std::path::PathBuf],
    iterations: usize,
) -> Result<std::time::Duration> {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let iter_start = Instant::now();
        for path in segment_paths {
            let raw = tokio::fs::read_to_string(path).await?;
            if raw.is_empty() {
                continue;
            }
        }
        samples.push(iter_start.elapsed());
    }

    samples.sort_unstable();
    Ok(samples[samples.len() / 2])
}

async fn measure_lists_branch_indexing(
    operand: &str,
    list_payload: &str,
) -> Result<std::time::Duration> {
    let entries = parse_payload_entries(list_payload);
    let mode = if operand == "lists.domains_regexp" {
        ListsDomainsRegexpCacheMode::AhoAndCompiled
    } else {
        ListsDomainsRegexpCacheMode::CompiledOnly
    };
    RuleService::probe_measure_lists_indexing_latency(operand, &entries, false, mode)
}

fn parse_payload_entries(list_payload: &str) -> Vec<String> {
    list_payload
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn build_equalized_payload<F>(mut lines: Vec<String>, target_len: usize, filler: F) -> String
where
    F: Fn(usize) -> String,
{
    while lines.len() < target_len {
        lines.push(filler(lines.len()));
    }
    let mut payload = lines.join("\n");
    payload.push('\n');
    payload
}

#[tokio::test]
async fn match_attempt_protocol_sensitive_respects_case_like_go() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-protocol-sensitive");

    write_rule_file(
        &rules_dir.path,
        "protocol-sensitive-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "protocol".to_string(),
            data: "TCP".to_string(),
            sensitive: true,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.151"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn match_attempt_uses_cached_list_entries_after_source_removal() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-rules");
    let list_dir = TestDir::new("rule-service-lists");
    tokio::fs::write(list_dir.path.join("domains.txt"), "0.0.0.0 example.org\n").await?;

    write_rule_file(
        &rules_dir.path,
        "cached-list",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    tokio::fs::remove_dir_all(&list_dir.path).await?;

    let decision = service
        .match_attempt(
            &probe_attempt("10.0.0.2"),
            &probe_process(),
            Some("example.org"),
        )
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );

    Ok(())
}

#[tokio::test]
async fn read_rules_dir_state_ignores_transient_list_temp_files() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-watch-state-rules");
    let list_dir = TestDir::new("rule-service-watch-state-lists");

    tokio::fs::write(list_dir.path.join("domains.txt"), "example.org\n").await?;
    write_rule_file(
        &rules_dir.path,
        "watch-state-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let before = RuleService::read_rules_dir_file_state_async(&rules_dir.path)
        .await
        .expect("state before temp files");

    tokio::fs::write(list_dir.path.join("domains.txt.download"), "tmp\n").await?;
    tokio::fs::write(list_dir.path.join("domains.txt.tmp"), "tmp\n").await?;
    tokio::fs::write(list_dir.path.join(".domains.txt.swp"), "tmp\n").await?;

    let after = RuleService::read_rules_dir_file_state_async(&rules_dir.path)
        .await
        .expect("state after temp files");

    assert_eq!(before, after);
    Ok(())
}

#[tokio::test]
async fn match_attempt_domain_lists_with_prefixed_space_comment_behaves_like_go() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-domain-list-prefixed-space-comment");
    let list_dir = TestDir::new("rule-service-domain-list-prefixed-space-comment-lists");
    tokio::fs::write(
        list_dir.path.join("domains.txt"),
        " #0.0.0.0 example.org\n0.0.0.0 allowed.example\n",
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "domain-list-space-comment",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(
            &probe_attempt("10.0.0.163"),
            &probe_process(),
            Some("example.org"),
        )
        .await?;

    assert_eq!(decision, None);
    Ok(())
}

#[tokio::test]
async fn match_attempt_domain_lists_accepts_plain_domain_entries() -> Result<()> {
    // Plain domain lines (no 0.0.0.0/127.0.0.1 prefix) are now accepted by
    // lists.domains — the trie/glob index handles them, which is more efficient
    // than routing plain domain lists through lists.domains_regexp (AhoCorasick).
    let rules_dir = TestDir::new("rule-service-domain-list-filter");
    let list_dir = TestDir::new("rule-service-domain-list-filter-lists");
    tokio::fs::write(list_dir.path.join("domains.txt"), "example.org\n").await?;

    write_rule_file(
        &rules_dir.path,
        "domain-list-filter",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(
            &probe_attempt("10.0.0.16"),
            &probe_process(),
            Some("example.org"),
        )
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
// Previously this asserted None (no match), mirroring Go's behaviour where only the
// incoming candidate was lowercased while the list entry was stored verbatim.
// The list entry is now normalised to lower-case in normalize_domain_list_entry, so a
// mixed-case entry ("0.0.0.0 Example.org") must match a lower-case candidate.
async fn match_attempt_domain_lists_normalizes_list_entry_case() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-domain-list-candidate-lower-only");
    let list_dir = TestDir::new("rule-service-domain-list-candidate-lower-only-lists");
    tokio::fs::write(list_dir.path.join("domains.txt"), "0.0.0.0 Example.org\n").await?;

    write_rule_file(
        &rules_dir.path,
        "domain-list-case",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(
            &probe_attempt("10.0.0.161"),
            &probe_process(),
            Some("example.org"),
        )
        .await?;

    // The mixed-case list entry is stored as "example.org"; it must match.
    assert!(decision.is_some());
    Ok(())
}

#[tokio::test]
async fn match_attempt_hash_list_requires_md5_value() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-hash-list");
    let list_dir = TestDir::new("rule-service-hash-list-lists");
    tokio::fs::write(list_dir.path.join("hashes.txt"), "hash-value\n").await?;

    write_rule_file(
        &rules_dir.path,
        "hash-list",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.hash.md5".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let mut process = probe_process();
    process.process_hash_md5 = None;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.17"), &process, Some("example.org"))
        .await?;

    assert_eq!(decision, None);
    Ok(())
}

#[tokio::test]
async fn match_attempt_domains_regexp_insensitive_only_lowercases_candidate_like_go() -> Result<()>
{
    let rules_dir = TestDir::new("rule-service-domain-regexp-candidate-lower-only");
    let list_dir = TestDir::new("rule-service-domain-regexp-candidate-lower-only-lists");
    tokio::fs::write(
        list_dir.path.join("domainsregexp.txt"),
        "^EXAMPLE\\\\.ORG$\n",
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "domain-regexp-case",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains_regexp".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(
            &probe_attempt("10.0.0.162"),
            &probe_process(),
            Some("example.org"),
        )
        .await?;

    assert_eq!(decision, None);
    Ok(())
}

#[tokio::test]
async fn load_path_decodes_legacy_list_operator_data() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-legacy-list-data");
    let raw_rule = r#"{
    "name": "legacy-list",
    "action": "deny",
    "duration": "always",
    "enabled": true,
    "operator": {
        "type": "list",
        "operand": "list",
        "data": "[{\"type\":\"simple\",\"operand\":\"process.path\",\"data\":\"/usr/bin/curl\",\"sensitive\":false}]",
        "list": []
  }
}"#;
    tokio::fs::write(rules_dir.path.join("legacy-list.json"), raw_rule).await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.18"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn load_path_matches_blocklist_subscription_rule_shape_with_null_child_lists() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-subscription-shape");
    let list_root = TestDir::new("rule-service-subscription-shape-lists");
    let list_dir = list_root
        .path
        .join(".config/opensnitch/list_subscriptions/rules.list.d/hagezi-pro-hosts");
    tokio::fs::create_dir_all(&list_dir).await?;
    let hagezi_tail_artifact = concat!(
        "0.0.0.0 zzzmjfixezere.site\n",
        "0.0.0.0 www.zzzmjfixezere.site\n",
        "0.0.0.0 zzzmyl.com\n",
        "0.0.0.0 www.zzzmyl.com\n",
        "0.0.0.0 zzzperform.com\n",
        "0.0.0.0 www.zzzperform.com\n",
        "0.0.0.0 tr.zzztube.com\n",
        "0.0.0.0 tr.zzztube.tv\n",
        "0.0.0.0 zzzzfzgzbz.com\n",
        "0.0.0.0 www.zzzzfzgzbz.com\n",
    );
    tokio::fs::write(
        list_dir.join("00-hagezi-pro-hosts.txt"),
        hagezi_tail_artifact,
    )
    .await?;

    let raw_rule = format!(
        r#"{{
    "created": "2026-03-14T11:24:36+01:00",
    "updated": "2026-03-14T11:24:36+01:00",
    "name": "00-blocklist-hagezi-pro-hosts",
    "description": "From list subscription : hagezi-pro-hosts.txt",
    "action": "deny",
    "duration": "always",
    "operator": {{
        "operand": "list",
        "data": "",
        "type": "list",
        "list": [
            {{
                "operand": "user.id",
                "data": "1000",
                "type": "simple",
                "list": null,
                "sensitive": false
            }},
            {{
                "operand": "lists.domains",
                "data": "{}",
                "type": "lists",
                "list": null,
                "sensitive": false
            }}
        ],
        "sensitive": false
    }},
    "enabled": true,
    "precedence": false,
    "nolog": false
}}"#,
        list_dir.display()
    );

    tokio::fs::write(
        rules_dir.path.join("00-blocklist-hagezi-pro-hosts.json"),
        raw_rule,
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let matched = service
        .match_attempt(
            &probe_attempt("10.0.0.44"),
            &probe_process(),
            Some("zzzmjfixezere.site"),
        )
        .await?;
    assert_eq!(
        matched,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );

    let mut non_matching_uid_attempt = probe_attempt("10.0.0.44");
    non_matching_uid_attempt.uid = 2000;
    let unmatched = service
        .match_attempt(
            &non_matching_uid_attempt,
            &probe_process(),
            Some("zzzmjfixezere.site"),
        )
        .await?;
    assert_eq!(unmatched, None);

    Ok(())
}

#[tokio::test]
async fn blocklist_subscription_rule_loads_all_txt_files_in_list_directory() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-subscription-multifile");
    let list_root = TestDir::new("rule-service-subscription-multifile-lists");
    let list_dir = list_root
        .path
        .join(".config/opensnitch/list_subscriptions/rules.list.d/hagezi-pro-hosts");
    tokio::fs::create_dir_all(&list_dir).await?;

    tokio::fs::write(
        list_dir.join("00-hagezi-pro-hosts.txt"),
        concat!("0.0.0.0 alpha.example\n", "0.0.0.0 duplicate.example\n",),
    )
    .await?;
    tokio::fs::write(
        list_dir.join("01-hagezi-pro-hosts-extra.txt"),
        concat!("0.0.0.0 beta.example\n", "0.0.0.0 duplicate.example\n",),
    )
    .await?;

    let raw_rule = format!(
        r#"{{
  "name": "00-blocklist-hagezi-pro-hosts",
  "action": "deny",
  "duration": "always",
  "enabled": true,
  "operator": {{
    "operand": "list",
    "data": "",
    "type": "list",
    "list": [
      {{
        "operand": "user.id",
        "data": "1000",
        "type": "simple",
        "list": null,
        "sensitive": false
      }},
      {{
        "operand": "lists.domains",
        "data": "{}",
        "type": "lists",
        "list": null,
        "sensitive": false
      }}
    ],
    "sensitive": false
  }}
}}"#,
        list_dir.display()
    );
    tokio::fs::write(
        rules_dir.path.join("00-blocklist-hagezi-pro-hosts.json"),
        raw_rule,
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let process = probe_process();
    let attempt = probe_attempt("10.0.0.45");

    let alpha = service
        .match_attempt(&attempt, &process, Some("alpha.example"))
        .await?;
    let beta = service
        .match_attempt(&attempt, &process, Some("beta.example"))
        .await?;

    assert_eq!(
        alpha,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    assert_eq!(
        beta,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );

    Ok(())
}

#[tokio::test]
async fn blocklist_large_segments_load_and_latency_smoke() -> Result<()> {
    let default_path = format!(
        "{}/.config/opensnitch/list_subscriptions/rules.list.d/hagezi-pro-hosts/00-hagezi-pro-hosts.txt",
        std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()),
    );
    let explicit = std::env::var("OPENSNITCH_LARGE_SEGMENT_FIXTURE").ok();
    let fixture_path = explicit.as_deref().unwrap_or(&default_path);

    // Prefer the full local list for a high-fidelity smoke; fall back to the
    // sampled fixture that is always present in the repository.
    let bundled = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/testdata/hagezi-pro-hosts-sample.txt"
    );
    let source_path = if std::path::Path::new(fixture_path).exists() {
        std::path::PathBuf::from(fixture_path)
    } else {
        tracing::info!("full hosts list not found at {fixture_path}; using bundled sample fixture");
        std::path::PathBuf::from(bundled)
    };

    let source_raw = tokio::fs::read_to_string(&source_path).await?;
    let domains: Vec<String> = source_raw
        .lines()
        .filter_map(|line| {
            if line.starts_with("0.0.0.0 ") {
                return Some(line[8..].trim().to_string());
            }
            if line.starts_with("127.0.0.1 ") {
                return Some(line[10..].trim().to_string());
            }
            None
        })
        .filter(|value| !value.is_empty())
        .collect();

    if domains.len() < 20 {
        tracing::info!("skip: source artifact too small for segmentation smoke test");
        return Ok(());
    }

    let rules_dir = TestDir::new("rule-service-subscription-large-segments");
    let list_root = TestDir::new("rule-service-subscription-large-segments-lists");
    let list_dir = list_root
        .path
        .join(".config/opensnitch/list_subscriptions/rules.list.d/hagezi-pro-hosts");
    tokio::fs::create_dir_all(&list_dir).await?;

    let segment_count = 8_usize;
    let mut segments: Vec<Vec<String>> = vec![Vec::new(); segment_count];
    for (idx, domain) in domains.iter().enumerate() {
        segments[idx % segment_count].push(domain.clone());
    }

    let mut segment_paths = Vec::with_capacity(segment_count);
    for (idx, segment) in segments.iter().enumerate() {
        let mut content = String::new();
        for domain in segment {
            content.push_str("0.0.0.0 ");
            content.push_str(domain);
            content.push('\n');
        }
        let segment_path = list_dir.join(format!("{:02}-segment.txt", idx));
        tokio::fs::write(&segment_path, content).await?;
        segment_paths.push(segment_path);
    }

    let plain_entries = RuleService::probe_load_list_entries_async_plain(&list_dir).await?;
    assert!(!plain_entries.is_empty());

    let raw_rule = format!(
        r#"{{
  "name": "00-blocklist-hagezi-pro-hosts",
  "action": "deny",
  "duration": "always",
  "enabled": true,
  "operator": {{
    "operand": "list",
    "data": "",
    "type": "list",
    "list": [
      {{
        "operand": "user.id",
        "data": "1000",
        "type": "simple",
        "list": null,
        "sensitive": false
      }},
      {{
        "operand": "lists.domains",
        "data": "{}",
        "type": "lists",
        "list": null,
        "sensitive": false
      }}
    ],
    "sensitive": false
  }}
}}"#,
        list_dir.display()
    );
    tokio::fs::write(
        rules_dir.path.join("00-blocklist-hagezi-pro-hosts.json"),
        raw_rule,
    )
    .await?;

    let load_iterations = 25usize;
    let elapsed = measure_segment_file_load_median_latency(&segment_paths, load_iterations).await?;

    tracing::info!(
        "large-segment load latency (median total of {} segments over {} iters): {:?} for {} domains",
        segment_count,
        load_iterations,
        elapsed,
        domains.len()
    );

    let branch_iterations = 100_000usize;
    let sample_len = 10_000usize;

    let domains_exact_payload = build_equalized_payload(
        vec!["0.0.0.0 api.example.org".to_string()],
        sample_len,
        |i| format!("0.0.0.0 filler-{i}.domains.example.net"),
    );
    let domains_wildcard_payload =
        build_equalized_payload(vec!["0.0.0.0 *.example.org".to_string()], sample_len, |i| {
            format!("0.0.0.0 *.filler-{i}.wild.example.net")
        });
    let domains_glob_payload = build_equalized_payload(
        vec!["0.0.0.0 api-??.example.org".to_string()],
        sample_len,
        |i| format!("0.0.0.0 svc-{:02}.glob{}.example.org", i % 100, i % 37),
    );
    let nets_exact_payload =
        build_equalized_payload(vec!["10.0.0.46".to_string()], sample_len, |i| {
            format!("172.16.{}.{}", i / 254, (i % 254) + 1)
        });
    let nets_cidr_payload =
        build_equalized_payload(vec!["10.0.0.0/24".to_string()], sample_len, |i| {
            format!("172.{}.0.0/16", (i % 250) + 1)
        });
    let ips_exact_payload =
        build_equalized_payload(vec!["10.0.0.46".to_string()], sample_len, |i| {
            format!("192.168.{}.{}", i / 254, (i % 254) + 1)
        });
    let ips_cidr_payload =
        build_equalized_payload(vec!["10.0.0.0/24".to_string()], sample_len, |i| {
            format!("192.{}.0.0/16", (i % 250) + 1)
        });
    let domains_regexp_payload = build_equalized_payload(
        vec![
            "^api\\.example\\.org$".to_string(),
            "^(?:[a-z0-9-]+\\.)*example\\.org$".to_string(),
            "^(?:cdn|img|static)\\d{1,2}\\.example\\.(?:org|net)$".to_string(),
            "^[a-z]{3,10}\\d{2}\\.service\\.(?:prod|staging)\\.example\\.org$".to_string(),
            "^(?:service|api)-[a-z0-9-]+\\.example\\.org$".to_string(),
        ],
        sample_len,
        |i| {
            format!(
                "^(?:node|edge)-[a-z0-9]{{4}}\\.zone{}\\.example\\.(?:org|net)$",
                i % 31
            )
        },
    );

    let domains_exact_index =
        measure_lists_branch_indexing("lists.domains", &domains_exact_payload).await?;
    tracing::info!(
        "branch lists.domains Warm [HashSet<String>] indexing: cold={:?}",
        domains_exact_index
    );
    let (domains_match, domains_hits) = measure_lists_branch_matching(
        "lists.domains",
        &domains_exact_payload,
        "10.0.0.46",
        Some("api.example.org"),
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.domains Warm [HashSet<String>] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / domains_match.as_secs_f64().max(1e-9),
        domains_hits,
        domains_match
    );

    let wildcard_index =
        measure_lists_branch_indexing("lists.domains", &domains_wildcard_payload).await?;
    tracing::info!(
        "branch lists.domains Cold [DomainWildcardTrie fallback] indexing: cold={:?}",
        wildcard_index
    );
    let (wildcard_match, wildcard_hits) = measure_lists_branch_matching(
        "lists.domains",
        &domains_wildcard_payload,
        "10.0.0.46",
        Some("svc.api.example.org"),
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.domains Cold [DomainWildcardTrie fallback] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / wildcard_match.as_secs_f64().max(1e-9),
        wildcard_hits,
        wildcard_match
    );

    let glob_index = measure_lists_branch_indexing("lists.domains", &domains_glob_payload).await?;
    tracing::info!(
        "branch lists.domains Cold [GlobMatcher fallback] indexing: cold={:?}",
        glob_index
    );
    let (glob_match, glob_hits) = measure_lists_branch_matching(
        "lists.domains",
        &domains_glob_payload,
        "10.0.0.46",
        Some("api-12.example.org"),
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.domains Cold [GlobMatcher fallback] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / glob_match.as_secs_f64().max(1e-9),
        glob_hits,
        glob_match
    );

    let nets_exact_index = measure_lists_branch_indexing("lists.nets", &nets_exact_payload).await?;
    tracing::info!(
        "branch lists.nets Warm [HashSet<String> exact] indexing: cold={:?}",
        nets_exact_index
    );
    let (nets_exact, nets_exact_hits) = measure_lists_branch_matching(
        "lists.nets",
        &nets_exact_payload,
        "10.0.0.46",
        None,
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.nets Warm [HashSet<String> exact] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / nets_exact.as_secs_f64().max(1e-9),
        nets_exact_hits,
        nets_exact
    );

    let nets_index = measure_lists_branch_indexing("lists.nets", &nets_cidr_payload).await?;
    tracing::info!(
        "branch lists.nets Cold [CidrTrieIndex] indexing: cold={:?}",
        nets_index
    );
    let (nets_match, nets_hits) = measure_lists_branch_matching(
        "lists.nets",
        &nets_cidr_payload,
        "10.0.0.46",
        None,
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.nets Cold [CidrTrieIndex] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / nets_match.as_secs_f64().max(1e-9),
        nets_hits,
        nets_match
    );

    let ips_exact_index = measure_lists_branch_indexing("lists.ips", &ips_exact_payload).await?;
    tracing::info!(
        "branch lists.ips Warm [HashSet<String> exact] indexing: cold={:?}",
        ips_exact_index
    );
    let (ips_exact, ips_exact_hits) = measure_lists_branch_matching(
        "lists.ips",
        &ips_exact_payload,
        "10.0.0.46",
        None,
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.ips Warm [HashSet<String> exact] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / ips_exact.as_secs_f64().max(1e-9),
        ips_exact_hits,
        ips_exact
    );

    let ips_index = measure_lists_branch_indexing("lists.ips", &ips_cidr_payload).await?;
    tracing::info!(
        "branch lists.ips Cold [CidrTrieIndex] indexing: cold={:?}",
        ips_index
    );
    let (ips_match, ips_hits) = measure_lists_branch_matching(
        "lists.ips",
        &ips_cidr_payload,
        "10.0.0.46",
        None,
        branch_iterations,
    )
    .await?;
    tracing::info!(
        "branch lists.ips Cold [CidrTrieIndex] matching: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / ips_match.as_secs_f64().max(1e-9),
        ips_hits,
        ips_match
    );

    let regex_entries = parse_payload_entries(&domains_regexp_payload);
    let regex_index_aho = RuleService::probe_measure_lists_indexing_latency(
        "lists.domains_regexp",
        &regex_entries,
        false,
        ListsDomainsRegexpCacheMode::AhoAndCompiled,
    )?;
    tracing::info!(
        "branch lists.domains_regexp indexing [Aho+compiled regex]: cold={:?}",
        regex_index_aho
    );
    let (regex_match_aho, regex_hits_aho) = RuleService::probe_measure_lists_matching_latency(
        "lists.domains_regexp",
        &regex_entries,
        false,
        "10.0.0.46",
        Some("cdn12.example.net"),
        branch_iterations,
        ListsDomainsRegexpCacheMode::AhoAndCompiled,
    )?;
    tracing::info!(
        "branch lists.domains_regexp matching [Aho+compiled regex]: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / regex_match_aho.as_secs_f64().max(1e-9),
        regex_hits_aho,
        regex_match_aho
    );

    let regex_index_compiled = RuleService::probe_measure_lists_indexing_latency(
        "lists.domains_regexp",
        &regex_entries,
        false,
        ListsDomainsRegexpCacheMode::CompiledOnly,
    )?;
    tracing::info!(
        "branch lists.domains_regexp indexing [CompiledRegex only]: cold={:?}",
        regex_index_compiled
    );
    let (regex_match_compiled, regex_hits_compiled) =
        RuleService::probe_measure_lists_matching_latency(
            "lists.domains_regexp",
            &regex_entries,
            false,
            "10.0.0.46",
            Some("cdn12.example.net"),
            branch_iterations,
            ListsDomainsRegexpCacheMode::CompiledOnly,
        )?;
    tracing::info!(
        "branch lists.domains_regexp matching [CompiledRegex only]: cold={:.0} ops/s ({} matches in {:?})",
        (branch_iterations as f64) / regex_match_compiled.as_secs_f64().max(1e-9),
        regex_hits_compiled,
        regex_match_compiled
    );

    Ok(())
}

#[tokio::test]
async fn match_attempt_uses_cached_network_aliases_after_source_removal() -> Result<()> {
    let previous_aliases = std::env::var_os("OPENSNITCH_NETWORK_ALIASES_FILE");
    let rules_dir = TestDir::new("rule-service-rules");
    let alias_dir = TestDir::new("rule-service-aliases");
    let alias_file = alias_dir.path.join("network_aliases.json");
    tokio::fs::write(&alias_file, r#"{"corp":["10.10.0.0/16"]}"#).await?;
    unsafe {
        std::env::set_var("OPENSNITCH_NETWORK_ALIASES_FILE", &alias_file);
    }

    write_rule_file(
        &rules_dir.path,
        "cached-alias",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "network".to_string(),
            operand: "dest.network".to_string(),
            data: "corp".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    tokio::fs::remove_file(&alias_file).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.10.4.7"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );

    if let Some(value) = previous_aliases {
        unsafe {
            std::env::set_var("OPENSNITCH_NETWORK_ALIASES_FILE", value);
        }
    } else {
        unsafe {
            std::env::remove_var("OPENSNITCH_NETWORK_ALIASES_FILE");
        }
    }

    Ok(())
}

#[tokio::test]
async fn match_attempt_maps_allow_and_reject_actions() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-actions");

    write_rule_file(
        &rules_dir.path,
        "allow-rule",
        "allow",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "reject-rule",
        "reject",
        true,
        true,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.9"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: true,
            nolog: false,
        })
    );

    Ok(())
}

#[tokio::test]
async fn match_attempt_returns_none_when_no_rule_matches() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-no-match");

    write_rule_file(
        &rules_dir.path,
        "non-matching-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/definitely/not/the/current/process".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.10"), &probe_process(), None)
        .await?;

    assert_eq!(decision, None);
    Ok(())
}

#[tokio::test]
async fn match_attempt_deny_short_circuits_before_later_allow() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-last-wins");

    write_rule_file(
        &rules_dir.path,
        "001-first-deny",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "002-second-allow",
        "allow",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.11"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );

    Ok(())
}

#[tokio::test]
async fn match_attempt_ignores_disabled_matching_rule() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-disabled");

    write_rule_file(
        &rules_dir.path,
        "disabled-deny",
        "deny",
        false,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.12"), &probe_process(), None)
        .await?;

    assert_eq!(decision, None);
    Ok(())
}

#[tokio::test]
async fn match_attempt_matches_parent_process_path_operand() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-parent-path");

    write_rule_file(
        &rules_dir.path,
        "parent-path-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.parent.path".to_string(),
            data: "/sbin/init".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.13"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn match_attempt_matches_process_env_operand() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-env");

    write_rule_file(
        &rules_dir.path,
        "env-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.env.FOO".to_string(),
            data: "bar".to_string(),
            sensitive: true,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.14"), &probe_process_with_env(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn match_attempt_matches_protocol_operand() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-protocol");

    write_rule_file(
        &rules_dir.path,
        "protocol-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "protocol".to_string(),
            data: "TCP".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.15"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn upsert_once_rule_returns_decision_without_persisting() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-once-upsert");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = upsert_rule(
        &service,
        WireRule {
            name: "temp-once".to_string(),
            action: "deny".to_string(),
            duration: "once".to_string(),
            enabled: true,
            operator: Some(WireRuleOperator {
                type_name: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await?;

    assert_eq!(
        decision,
        RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        }
    );
    assert!(service.list_wire().await.is_empty());
    assert!(!rules_dir.path.join("temp-once.json").exists());
    Ok(())
}

#[tokio::test]
async fn upsert_persistent_rule_updates_existing_record() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-persistent-upsert");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let initial = WireRule {
        name: "persisted".to_string(),
        action: "allow".to_string(),
        duration: "always".to_string(),
        enabled: true,
        operator: Some(WireRuleOperator {
            type_name: "simple".to_string(),
            operand: "true".to_string(),
            data: String::new(),
            sensitive: false,
            list: Vec::new(),
        }),
        ..Default::default()
    };

    upsert_rule(&service, initial.clone()).await?;

    let updated = WireRule {
        action: "reject".to_string(),
        ..initial
    };
    let decision = upsert_rule(&service, updated).await?;

    assert_eq!(
        decision,
        RuleMatchDecision {
            allow: false,
            reject: true,
            nolog: false,
        }
    );

    let list = service.list_wire().await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "persisted");
    assert_eq!(list[0].action, "reject");
    assert!(rules_dir.path.join("persisted.json").exists());
    Ok(())
}

#[tokio::test]
async fn precedence_rule_overrides_following_non_precedence_matches() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-precedence-order");

    write_rule_file(
        &rules_dir.path,
        "001-precedence-reject",
        "reject",
        true,
        true,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "002-non-precedence-allow",
        "allow",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.21"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: true,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn protocol_operand_is_case_insensitive_when_not_sensitive() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-protocol-case");

    write_rule_file(
        &rules_dir.path,
        "protocol-case-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "protocol".to_string(),
            data: "tCp".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.22"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn process_env_operand_does_not_match_when_key_is_missing() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-env-missing");

    write_rule_file(
        &rules_dir.path,
        "env-missing-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.env.MISSING".to_string(),
            data: "value".to_string(),
            sensitive: true,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.23"), &probe_process_with_env(), None)
        .await?;

    assert_eq!(decision, None);
    Ok(())
}

#[tokio::test]
async fn range_operand_matches_dest_port_range() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-range-port");

    write_rule_file(
        &rules_dir.path,
        "port-range-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "range".to_string(),
            operand: "dest.port".to_string(),
            data: "400-500".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let decision = service
        .match_attempt(&probe_attempt("10.0.0.24"), &probe_process(), None)
        .await?;

    assert_eq!(
        decision,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn delete_by_name_is_idempotent_for_missing_rule() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-delete-idempotent");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    service.delete_by_name("does-not-exist").await?;
    service.delete_by_name("does-not-exist").await?;

    assert!(service.list_wire().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn load_path_skips_invalid_enabled_regexp_rule() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-invalid-regexp-load");

    write_rule_file(
        &rules_dir.path,
        "001-invalid-regexp",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "regexp".to_string(),
            operand: "protocol".to_string(),
            data: "^TC(P$".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "002-valid-simple",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "process.path".to_string(),
            data: "/usr/bin/curl".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let rules = service.list_wire().await;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "002-valid-simple");

    Ok(())
}

#[tokio::test]
async fn upsert_enabled_invalid_regexp_returns_error() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-invalid-regexp-upsert");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let result = upsert_rule(
        &service,
        WireRule {
            name: "invalid-regexp-upsert".to_string(),
            action: "deny".to_string(),
            duration: "always".to_string(),
            enabled: true,
            operator: Some(WireRuleOperator {
                type_name: "regexp".to_string(),
                operand: "protocol".to_string(),
                data: "^TC(P$".to_string(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await;

    assert!(result.is_err());
    assert!(service.list_wire().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn upsert_enabled_without_operator_returns_error() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-missing-operator-upsert");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let result = upsert_rule(
        &service,
        WireRule {
            name: "missing-operator".to_string(),
            action: "deny".to_string(),
            duration: "always".to_string(),
            enabled: true,
            operator: None,
            ..Default::default()
        },
    )
    .await;

    assert!(result.is_err());
    assert!(service.list_wire().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn upsert_enabled_unknown_user_name_returns_error() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-unknown-user-upsert");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let result = upsert_rule(
        &service,
        WireRule {
            name: "unknown-user-name".to_string(),
            action: "deny".to_string(),
            duration: "always".to_string(),
            enabled: true,
            operator: Some(WireRuleOperator {
                type_name: "simple".to_string(),
                operand: "user.name".to_string(),
                data: "opensnitch-user-that-should-not-exist".to_string(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await;

    assert!(result.is_err());
    assert!(service.list_wire().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn load_path_keeps_disabled_invalid_regexp_rule() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-disabled-invalid-regexp-load");

    write_rule_file(
        &rules_dir.path,
        "disabled-invalid-regexp",
        "deny",
        false,
        false,
        RuleFileOperator {
            r#type: "regexp".to_string(),
            operand: "protocol".to_string(),
            data: "^TC(P$".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let rules = service.list_wire().await;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "disabled-invalid-regexp");
    assert!(!rules[0].enabled);

    Ok(())
}

#[tokio::test]
async fn load_path_returns_error_for_missing_directory() -> Result<()> {
    let service = RuleService::default();
    let dir = TestDir::new("rule-service-missing-dir");
    let missing = dir.path.join("missing");

    let result = service.load_path(&missing).await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn load_path_sorts_rules_by_name() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-order");

    write_rule_file(
        &rules_dir.path,
        "002-second",
        "allow",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "true".to_string(),
            data: String::new(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "001-first",
        "allow",
        true,
        false,
        RuleFileOperator {
            r#type: "simple".to_string(),
            operand: "true".to_string(),
            data: String::new(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    let listed = service.list_wire().await;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].name, "001-first");
    assert_eq!(listed[1].name, "002-second");
    Ok(())
}

#[tokio::test]
async fn temporary_rule_expires_after_duration() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-temp-expiry");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    upsert_rule(
        &service,
        WireRule {
            name: "temp-expire".to_string(),
            action: "allow".to_string(),
            duration: "150ms".to_string(),
            enabled: true,
            operator: Some(WireRuleOperator {
                type_name: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await?;

    assert_eq!(service.list_wire().await.len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(service.list_wire().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn temporary_rule_duration_change_prevents_old_timer_deletion() -> Result<()> {
    let rules_dir = TestDir::new("rule-service-temp-duration-change");
    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    upsert_rule(
        &service,
        WireRule {
            name: "temp-change".to_string(),
            action: "allow".to_string(),
            duration: "150ms".to_string(),
            enabled: true,
            operator: Some(WireRuleOperator {
                type_name: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    upsert_rule(
        &service,
        WireRule {
            name: "temp-change".to_string(),
            action: "allow".to_string(),
            duration: "1h".to_string(),
            enabled: true,
            operator: Some(WireRuleOperator {
                type_name: "simple".to_string(),
                operand: "true".to_string(),
                data: String::new(),
                sensitive: false,
                list: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await?;

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let listed = service.list_wire().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "temp-change");
    Ok(())
}

#[tokio::test]
async fn match_attempt_domain_lists_parses_adblock_adguard_format() -> Result<()> {
    // Verify conformance with the AdGuard Home Hosts-Blocklists spec and the
    // Adblock Plus filter cheatsheet:
    //   https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists
    //   https://adblockplus.org/filter-cheatsheet
    let rules_dir = TestDir::new("rule-service-adblock-rules");
    let list_dir = TestDir::new("rule-service-adblock-lists");

    tokio::fs::write(
        list_dir.path.join("adblock.txt"),
        concat!(
            "[Adblock Plus 2.0]\n",
            "! AdBlock comment — header metadata\n",
            "# hosts-style comment\n",
            "@@||allowlisted.example.com^\n", // exception rule: skip
            "||ads.example.com^\n",           // plain anchor: exact + subdomains
            "||*.tracker.net^\n",             // explicit wildcard: subdomains only
            "||CAPITAL.example.org^\n",       // case: must normalise
            "||blocked.com^$third-party\n",   // anchor + options: strip options
            "||path.example.net/resource^\n", // URL-style: strip path
            "example.com##.ad-banner\n",      // cosmetic filter: skip
            "example.com#@#.ad\n",            // cosmetic exception: skip
            "/regex-blocked\\.test\\.example/\n", // regex: applied via domains_regex cascade
            "|http://single-anchor.example|\n", // single-| URL anchor: skip
            "*$denyallow=com|net\n",          // modifier-only wildcard: skip
            "plain-domain.example\n",         // plain domain: exact only
            "inline.example # this is a comment\n", // inline comment: strip
            "0.0.0.0 hosts-format.example\n", // hosts format: exact only
        ),
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "adblock-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    // ||domain^ spec: blocks the domain AND all subdomains.
    // — exact domain match
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.1"),
            &probe_process(),
            Some("ads.example.com"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||ads.example.com^ must match the domain itself"
    );

    // — subdomain match (the key spec requirement)
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.11"),
            &probe_process(),
            Some("sub.ads.example.com"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||ads.example.com^ must match sub.ads.example.com"
    );

    // Explicit wildcard ||*.tracker.net^: matches subdomains only, NOT the domain itself.
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.2"),
            &probe_process(),
            Some("sub.tracker.net"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||*.tracker.net^ must match subdomain"
    );

    let miss_exact = service
        .match_attempt(
            &probe_attempt("10.0.0.12"),
            &probe_process(),
            Some("tracker.net"),
        )
        .await?;
    assert_eq!(
        miss_exact, None,
        "||*.tracker.net^ must NOT match exact tracker.net (no wildcard-only subdomain rule)"
    );

    // Case normalisation: CAPITAL.example.org → capital.example.org
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.3"),
            &probe_process(),
            Some("capital.example.org"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||CAPITAL.example.org^ must normalise to lowercase"
    );

    // Options stripped: blocked.com (with $third-party in list) must still match
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.4"),
            &probe_process(),
            Some("blocked.com"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||blocked.com^$third-party options must be stripped"
    );

    // Subdomain of options-stripped domain must also match
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.14"),
            &probe_process(),
            Some("sub.blocked.com"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "subdomain of ||blocked.com^$third-party must match"
    );

    // URL path stripped: ||path.example.net/resource^ → path.example.net
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.5"),
            &probe_process(),
            Some("path.example.net"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||path.example.net/resource^ path must be stripped"
    );

    // Exception rule (@@) must NOT produce a block match
    let miss = service
        .match_attempt(
            &probe_attempt("10.0.0.6"),
            &probe_process(),
            Some("allowlisted.example.com"),
        )
        .await?;
    assert_eq!(
        miss, None,
        "@@||allowlisted.example.com^ exception must be skipped"
    );

    // Cosmetic filter lines must NOT be added as domain entries
    let miss = service
        .match_attempt(
            &probe_attempt("10.0.0.7"),
            &probe_process(),
            Some("example.com"),
        )
        .await?;
    assert_eq!(
        miss, None,
        "example.com##.ad-banner cosmetic filter must be skipped"
    );

    // Regex rules are now applied via the domains_regex cascade (not skipped).
    // /regex-blocked\.test\.example/ matches the precise host only.
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.8"),
            &probe_process(),
            Some("regex-blocked.test.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "/regex-blocked\\.test\\.example/ must match via domains_regex cascade"
    );

    let miss = service
        .match_attempt(
            &probe_attempt("10.0.0.81"),
            &probe_process(),
            Some("other.test.example"),
        )
        .await?;
    assert_eq!(miss, None, "host not matching the precise regex must miss");

    // Single-| URL anchors must be skipped
    let miss = service
        .match_attempt(
            &probe_attempt("10.0.0.9"),
            &probe_process(),
            Some("single-anchor.example"),
        )
        .await?;
    assert_eq!(
        miss, None,
        "|http://...| single-anchor rule must be skipped"
    );

    // Modifier-only wildcard (*$denyallow=...) must be skipped (would match everything)
    // We verify this indirectly: an unrelated host should NOT match.
    let miss = service
        .match_attempt(
            &probe_attempt("10.0.0.10"),
            &probe_process(),
            Some("unrelated.tld"),
        )
        .await?;
    assert_eq!(miss, None, "*$denyallow modifier-only rule must be skipped");

    // Plain domain: exact only (no subdomains)
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.11"),
            &probe_process(),
            Some("plain-domain.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "plain domain must match exactly"
    );

    let miss = service
        .match_attempt(
            &probe_attempt("10.0.0.21"),
            &probe_process(),
            Some("sub.plain-domain.example"),
        )
        .await?;
    assert_eq!(miss, None, "plain domain entry must not match subdomains");

    // Inline comment stripping: `inline.example # this is a comment` → `inline.example`
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.12"),
            &probe_process(),
            Some("inline.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "inline # comment must be stripped from plain domain line"
    );

    // Hosts format: exact only
    let hit = service
        .match_attempt(
            &probe_attempt("10.0.0.13"),
            &probe_process(),
            Some("hosts-format.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "0.0.0.0 hosts-format must still work"
    );

    Ok(())
}

#[tokio::test]
async fn match_attempt_domain_lists_regex_cascade_in_domains_operand() -> Result<()> {
    // Verify that `lists.domains` transparently handles AdBlock-style `/pattern/`
    // regex entries found in mixed list files, mirroring the AdGuard urlfilter engine
    // design (single operand, cascaded dedicated caches).
    //
    // Cascade under test:
    //   HashSet (exact, O(1)) → DomainWildcardTrie → GlobMatcher → domains_regex
    //
    // The regex path is reached only when all structural lookups miss, so hosts that
    // match earlier layers remain unaffected.
    let rules_dir = TestDir::new("rule-service-domains-regex-cascade-rules");
    let list_dir = TestDir::new("rule-service-domains-regex-cascade-lists");

    tokio::fs::write(
        list_dir.path.join("mixed.txt"),
        concat!(
            "! comment line\n",
            "plain.example\n",         // exact domain → HashSet
            "||anchor.example^\n",     // AdBlock anchor → trie (domain+subdomains)
            "||*.wildcard.example^\n", // explicit wildcard anchor → trie (subdomains only)
            "/tracker\\.[a-z]+/\n",    // regex: matches e.g. tracker.net, tracker.io
            "/^ads\\./\n",             // regex: matches any host starting with "ads."
        ),
    )
    .await?;

    write_rule_file(
        &rules_dir.path,
        "domains-regex-cascade-rule",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "lists".to_string(),
            operand: "lists.domains".to_string(),
            data: path_string(&list_dir.path),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let service = RuleService::default();
    service.load_path(&rules_dir.path).await?;

    // — fast path: exact HashSet hit
    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.1"),
            &probe_process(),
            Some("plain.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "plain domain must hit via HashSet"
    );

    // — fast path: trie hit (AdBlock anchor — exact domain)
    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.2"),
            &probe_process(),
            Some("anchor.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||anchor.example^ must match the domain itself via trie"
    );

    // — fast path: trie hit (AdBlock anchor — subdomain)
    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.3"),
            &probe_process(),
            Some("sub.anchor.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||anchor.example^ must match sub.anchor.example via trie"
    );

    // — fast path: trie hit (explicit wildcard — subdomain only)
    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.4"),
            &probe_process(),
            Some("sub.wildcard.example"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "||*.wildcard.example^ must match subdomain via trie"
    );

    // — fall-through to domains_regex: /tracker\.[a-z]+/
    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.5"),
            &probe_process(),
            Some("tracker.net"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "/tracker\\.[a-z]+/ must match tracker.net via domains_regex cascade"
    );

    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.6"),
            &probe_process(),
            Some("tracker.io"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "/tracker\\.[a-z]+/ must match tracker.io via domains_regex cascade"
    );

    // — fall-through to domains_regex: /^ads\./
    let hit = service
        .match_attempt(
            &probe_attempt("10.1.0.7"),
            &probe_process(),
            Some("ads.example.com"),
        )
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "/^ads\\// must match ads.example.com via domains_regex cascade"
    );

    // — miss: a host that matches no layer
    let miss = service
        .match_attempt(
            &probe_attempt("10.1.0.8"),
            &probe_process(),
            Some("safe.example.org"),
        )
        .await?;
    assert_eq!(miss, None, "unmatched host must produce no verdict");

    Ok(())
}

#[tokio::test]
async fn network_aliases_file_loads_lan_and_cidr_entries() -> Result<()> {
    // Smoke-test that the legacy daemon/data/network_aliases.json file is
    // parseable and produces the expected alias names and that LAN private CIDRs
    // match correctly.
    let rules_dir = TestDir::new("rule-service-net-aliases");

    write_rule_file(
        &rules_dir.path,
        "block-lan",
        "deny",
        true,
        false,
        RuleFileOperator {
            r#type: "network".to_string(),
            operand: "dest.network".to_string(),
            data: "LAN".to_string(),
            sensitive: false,
            scope: None,
            list: Vec::new(),
        },
    )
    .await?;

    let dev_aliases = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("daemon/data/network_aliases.json");

    if !dev_aliases.exists() {
        // Path not present in CI without the full source tree — skip gracefully.
        return Ok(());
    }

    let mut service = RuleService::default();
    service.set_network_aliases_path(dev_aliases);
    service.load_path(&rules_dir.path).await?;

    // 10.0.0.1 is in 10.0.0.0/8 (LAN alias)
    let hit = service
        .match_attempt(&probe_attempt("10.0.0.1"), &probe_process(), None)
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "10.0.0.1 should match the LAN alias"
    );

    // 192.168.1.100 is in 192.168.0.0/16 (LAN alias)
    let hit = service
        .match_attempt(&probe_attempt("192.168.1.100"), &probe_process(), None)
        .await?;
    assert_eq!(
        hit,
        Some(RuleMatchDecision {
            allow: false,
            reject: false,
            nolog: false
        }),
        "192.168.1.100 should match the LAN alias"
    );

    // 8.8.8.8 is NOT in LAN
    let miss = service
        .match_attempt(&probe_attempt("8.8.8.8"), &probe_process(), None)
        .await?;
    assert_eq!(miss, None, "8.8.8.8 must not match the LAN alias");

    Ok(())
}

use std::path::PathBuf;

use opensnitch_proto::pb;

use crate::services::subscription::SubscriptionService;
use crate::services::subscription::format::validate_format_sample;
use crate::services::subscription::storage::SubscriptionStorage;
use crate::tests::support::{HttpFixture, HttpResponseFixture, TestDir, read_text};

fn make_service() -> SubscriptionService {
    SubscriptionService::new(SubscriptionStorage::in_memory(), "/tmp/test-sub-svc")
}

fn make_persistent_service(dir: &TestDir) -> (SubscriptionService, PathBuf) {
    let store_path = dir.path.join("subscriptions.json");
    let root_dir = dir.path.join("subscription-runtime");
    let storage = SubscriptionStorage::new(&store_path).expect("create file-backed store");
    (SubscriptionService::new(storage, &root_dir), store_path)
}

fn sample_sub(name: &str, url: &str) -> pb::Subscription {
    pb::Subscription {
        name: name.to_string(),
        url: url.to_string(),
        enabled: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn list_empty_returns_accepted() {
    let svc = make_service();
    let reply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::List as i32,
            ..Default::default()
        })
        .await;
    assert!(reply.accepted);
    assert!(reply.subscriptions.is_empty());
}

#[tokio::test]
async fn apply_then_list_round_trips() {
    let svc = make_service();
    let sub = sample_sub("hagezi-pro", "https://raw.example.com/hagezi.txt");

    let apply_reply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Apply as i32,
            subscriptions: vec![sub.clone()],
            ..Default::default()
        })
        .await;
    assert!(
        apply_reply.accepted,
        "apply failed: {}",
        apply_reply.message
    );
    assert_eq!(apply_reply.subscriptions.len(), 1);
    let stored_id = apply_reply.subscriptions[0].id.clone();
    assert!(!stored_id.is_empty(), "stored subscription must have an id");
    assert_eq!(apply_reply.subscriptions[0].interval_seconds, 24 * 3600);
    assert_eq!(apply_reply.subscriptions[0].timeout_seconds, 60);

    let list_reply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::List as i32,
            ..Default::default()
        })
        .await;
    assert!(list_reply.accepted);
    assert_eq!(list_reply.subscriptions.len(), 1);
    assert_eq!(list_reply.subscriptions[0].id, stored_id);
}

#[tokio::test]
async fn apply_no_items_is_rejected() {
    let svc = make_service();
    let reply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Apply as i32,
            ..Default::default()
        })
        .await;
    assert!(!reply.accepted);
}

#[tokio::test]
async fn delete_removes_subscription() {
    let svc = make_service();
    let sub = sample_sub("block-a", "https://example.com/a.txt");
    let apply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Apply as i32,
            subscriptions: vec![sub],
            ..Default::default()
        })
        .await;
    assert!(apply.accepted);

    let to_delete = apply.subscriptions.clone();
    let del = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Delete as i32,
            subscriptions: to_delete,
            ..Default::default()
        })
        .await;
    assert!(del.accepted);

    let list = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::List as i32,
            ..Default::default()
        })
        .await;
    assert!(
        list.subscriptions.is_empty(),
        "subscription should be deleted"
    );
}

#[tokio::test]
async fn refresh_downloads_source_and_persists_http_metadata() {
    let dir = TestDir::new("subscription-refresh-download");
    let server = HttpFixture::start(vec![HttpResponseFixture::new(
        "200 OK",
        vec![
            ("ETag".to_string(), "\"v1\"".to_string()),
            (
                "Last-Modified".to_string(),
                "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
            ),
        ],
        b"0.0.0.0 ads.example\n".to_vec(),
    )]);
    let (svc, store_path) = make_persistent_service(&dir);

    let apply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Apply as i32,
            subscriptions: vec![sample_sub("refresh-me", &server.url("/list.txt"))],
            ..Default::default()
        })
        .await;
    assert!(apply.accepted);

    let reply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Refresh as i32,
            force: true,
            ..Default::default()
        })
        .await;
    assert!(reply.accepted, "refresh failed: {:?}", reply.errors);
    assert_eq!(reply.subscriptions.len(), 1);
    assert_eq!(
        reply.subscriptions[0].status,
        pb::SubscriptionStatus::Ready as i32
    );

    let source_path = dir
        .path
        .join("subscription-runtime/sources.list.d")
        .join(&reply.subscriptions[0].filename);
    let source = read_text(&source_path);
    assert_eq!(source, "0.0.0.0 ads.example\n");

    let reloaded = SubscriptionStorage::new(&store_path).expect("reload store");
    let records = reloaded.list_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].etag, "\"v1\"");
    assert_eq!(records[0].last_modified, "Wed, 21 Oct 2015 07:28:00 GMT");
    assert_eq!(records[0].consecutive_failures, 0);
    assert!(records[0].next_refresh_after > crate::utils::time_nonce::unix_timestamp_now_utc());
}

#[tokio::test]
async fn refresh_uses_conditional_headers_for_not_modified_responses() {
    let dir = TestDir::new("subscription-refresh-conditional");
    let server = HttpFixture::start(vec![
        HttpResponseFixture::new(
            "200 OK",
            vec![
                ("ETag".to_string(), "\"etag-1\"".to_string()),
                (
                    "Last-Modified".to_string(),
                    "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
                ),
            ],
            b"127.0.0.1 example.org\n".to_vec(),
        ),
        HttpResponseFixture::new("304 Not Modified", vec![], Vec::<u8>::new()),
    ]);
    let (svc, _) = make_persistent_service(&dir);

    let apply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Apply as i32,
            subscriptions: vec![sample_sub("etag-check", &server.url("/etag.txt"))],
            ..Default::default()
        })
        .await;
    assert!(apply.accepted);

    let first = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Refresh as i32,
            force: true,
            ..Default::default()
        })
        .await;
    assert!(first.accepted);

    let second = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Refresh as i32,
            force: true,
            ..Default::default()
        })
        .await;
    assert!(second.accepted, "refresh failed: {:?}", second.errors);
    assert_eq!(
        second.subscriptions[0].status,
        pb::SubscriptionStatus::Ready as i32
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    let second_request = requests[1].to_lowercase();
    assert!(second_request.contains("if-none-match: \"etag-1\""));
    assert!(second_request.contains("if-modified-since: wed, 21 oct 2015 07:28:00 gmt"));
}

#[tokio::test]
async fn refresh_errors_back_off_and_skip_until_due() {
    let dir = TestDir::new("subscription-refresh-backoff");
    let server = HttpFixture::start(vec![HttpResponseFixture::new(
        "503 Service Unavailable",
        vec![],
        b"busy".to_vec(),
    )]);
    let (svc, store_path) = make_persistent_service(&dir);

    let apply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Apply as i32,
            subscriptions: vec![sample_sub("retry-me", &server.url("/retry.txt"))],
            ..Default::default()
        })
        .await;
    assert!(apply.accepted);

    let refresh = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Refresh as i32,
            force: true,
            ..Default::default()
        })
        .await;
    assert!(!refresh.accepted);
    assert_eq!(refresh.errors.len(), 1);

    let reloaded = SubscriptionStorage::new(&store_path).expect("reload store");
    let mut records = reloaded.list_records();
    assert_eq!(records.len(), 1);
    let record = records.remove(0);
    assert_eq!(record.status, "error");
    assert_eq!(record.consecutive_failures, 1);
    assert!(record.next_refresh_after > crate::utils::time_nonce::unix_timestamp_now_utc());
    assert!(record.last_error.contains("503"));

    let skipped = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Refresh as i32,
            ..Default::default()
        })
        .await;
    assert!(
        skipped.accepted,
        "skip reply should not fail: {:?}",
        skipped.errors
    );
    assert!(skipped.message.contains("1 skipped"));
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn counts_reflects_storage_state() {
    let svc = make_service();
    svc.handle_request(pb::SubscriptionRequest {
        operation: pb::SubscriptionAction::Apply as i32,
        subscriptions: vec![sample_sub("a", "https://a.example/a.txt")],
        ..Default::default()
    })
    .await;
    let ss = svc.subscription_stats();
    assert_eq!(ss.total, 1);
    assert_eq!(ss.ready, 0);
    assert_eq!(ss.error, 0);
}

#[tokio::test]
async fn unspecified_operation_is_rejected() {
    let svc = make_service();
    let reply = svc
        .handle_request(pb::SubscriptionRequest {
            operation: pb::SubscriptionAction::Unspecified as i32,
            ..Default::default()
        })
        .await;
    assert!(!reply.accepted);
}

fn lines(s: &str) -> Vec<String> {
    s.lines().map(str::to_owned).collect()
}

fn ok(format: &str, content: &str) {
    let sample = lines(content);
    assert!(
        validate_format_sample(format, &sample).is_ok(),
        "format={format:?} should accept:\n{content}"
    );
}

fn reject(format: &str, content: &str) {
    let sample = lines(content);
    assert!(
        validate_format_sample(format, &sample).is_err(),
        "format={format:?} should reject:\n{content}"
    );
}

#[test]
fn all_formats_accept_empty_file() {
    for fmt in &["hosts", "domains", "ips", "nets", "domain_regexps"] {
        ok(fmt, "");
    }
}

#[test]
fn all_formats_accept_comment_only_file() {
    let comments = "# OpenSnitch block list\n# Generated automatically\n";
    for fmt in &["hosts", "domains", "ips", "nets", "domain_regexps"] {
        ok(fmt, comments);
    }
}

#[test]
fn hosts_accepts_standard_blocklist() {
    ok(
        "hosts",
        "# block ads\n\
         0.0.0.0 ads.example.com\n\
         0.0.0.0 tracker.example.net\n",
    );
}

#[test]
fn hosts_accepts_127_prefix() {
    ok("hosts", "127.0.0.1 malware.example.com\n");
}

#[test]
fn hosts_accepts_ipv6_entries() {
    ok("hosts", "::1 localhost\n:: ads.bad.example\n");
}

#[test]
fn hosts_rejects_plain_domain_list() {
    reject("hosts", "ads.example.com\ntracker.example.net\n");
}

#[test]
fn hosts_rejects_json_payload() {
    reject("hosts", "{\"error\": \"not found\"}\n");
}

#[test]
fn hosts_rejects_html_error_page() {
    reject(
        "hosts",
        "<!DOCTYPE html>\n<html>\n<body>Error 403</body>\n</html>\n",
    );
}

#[test]
fn domains_accepts_plain_domain_list() {
    ok(
        "domains",
        "# plain domains\n\
         ads.example.com\n\
         tracker.example.net\n",
    );
}

#[test]
fn domains_accepts_wildcard_glob_entries() {
    ok(
        "domains",
        "*.ads.example.com\n\
         *.tracker.net\n\
         sub-1.example.co.uk\n",
    );
}

#[test]
fn domains_accepts_question_mark_glob() {
    ok("domains", "?.example.com\nwww.?.net\n");
}

#[test]
fn domains_rejects_hosts_format_lines() {
    reject("domains", "0.0.0.0 ads.example.com\n");
}

#[test]
fn domains_rejects_html_error_page() {
    reject(
        "domains",
        "<!DOCTYPE html>\n<html>\n<body>Error 403</body>\n</html>\n",
    );
}

#[test]
fn domains_rejects_json_payload() {
    reject("domains", "{\"blocked\": [\"ads.com\"]}\n");
}

#[test]
fn ips_accepts_ipv4_list() {
    ok(
        "ips",
        "# malicious IPs\n\
         1.2.3.4\n\
         5.6.7.8\n",
    );
}

#[test]
fn ips_accepts_ipv6_list() {
    ok(
        "ips",
        "2001:db8::1\n\
         ::ffff:192.0.2.1\n",
    );
}

#[test]
fn ips_rejects_cidr_lines() {
    reject("ips", "10.0.0.0/8\n192.168.0.0/16\n");
}

#[test]
fn ips_rejects_plain_domain_list() {
    reject("ips", "ads.example.com\ntracker.example.net\n");
}

#[test]
fn ips_rejects_html_error_page() {
    reject(
        "ips",
        "<!DOCTYPE html>\n<html>\n<body>Error 403</body>\n</html>\n",
    );
}

#[test]
fn nets_accepts_ipv4_cidr_list() {
    ok(
        "nets",
        "# blocked networks\n\
         10.0.0.0/8\n\
         192.168.1.0/24\n",
    );
}

#[test]
fn nets_accepts_ipv6_cidr_list() {
    ok("nets", "2001:db8::/32\nfe80::/10\n");
}

#[test]
fn nets_rejects_plain_ip_list() {
    reject("nets", "1.2.3.4\n5.6.7.8\n");
}

#[test]
fn nets_rejects_domain_list() {
    reject("nets", "ads.example.com\n");
}

#[test]
fn nets_rejects_html_error_page() {
    reject(
        "nets",
        "<!DOCTYPE html>\n<html>\n<body>504 Gateway Timeout</body>\n</html>\n",
    );
}

#[test]
fn domain_regexps_accepts_regexp_list() {
    ok(
        "domain_regexps",
        "# regexp block list\n\
         ^ads\\..*\\.example\\.com$\n\
         .*\\.tracker\\.net\n",
    );
}

#[test]
fn domain_regexps_accepts_simple_patterns() {
    ok("domain_regexps", "evil.example.com\n.*malware.*\n");
}

#[test]
fn domain_regexps_rejects_html_error_page() {
    reject(
        "domain_regexps",
        "<!DOCTYPE html>\n<html><body>Error 403</body></html>\n",
    );
}

#[test]
fn domain_regexps_rejects_json_payload() {
    reject("domain_regexps", "{\"error\": \"not found\"}\n");
}

#[test]
fn unknown_format_is_not_rejected() {
    ok("custom_hashes", "deadbeef0123456789abcdef\n");
}

#[test]
fn empty_format_treated_as_hosts() {
    ok("", "0.0.0.0 ads.example.com\n");
    reject("", "ads.example.com\n");
}

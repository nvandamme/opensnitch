use super::*;
use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread;

fn sample_connection() -> pb::Connection {
    pb::Connection {
        protocol: "tcp".to_string(),
        src_ip: "10.0.0.2".to_string(),
        src_port: 42424,
        dst_ip: "1.1.1.1".to_string(),
        dst_host: "one.one.one.one".to_string(),
        dst_port: 443,
        user_id: 1000,
        process_id: 4242,
        process_path: "/usr/bin/curl".to_string(),
        process_cwd: "/tmp".to_string(),
        process_args: vec!["curl".to_string(), "https://1.1.1.1".to_string()],
        process_env: std::collections::HashMap::new(),
        process_checksums: std::collections::HashMap::new(),
        process_tree: vec![],
    }
}

fn sample_rule() -> pb::Rule {
    pb::Rule {
        name: "allow-test".to_string(),
        action: "allow".to_string(),
        duration: "always".to_string(),
        enabled: true,
        nolog: false,
        ..Default::default()
    }
}

#[test]
fn retries_indefinitely_when_max_attempts_zero() {
    assert!(should_retry_connect(0, 1));
    assert!(should_retry_connect(0, 10));
    assert!(should_retry_connect(0, u16::MAX));
}

#[test]
fn retries_until_max_attempts_limit() {
    assert!(should_retry_connect(3, 1));
    assert!(should_retry_connect(3, 2));
    assert!(!should_retry_connect(3, 3));
}

#[test]
fn duration_parser_supports_common_units() {
    assert_eq!(
        parse_duration("150ms", Duration::from_secs(1)),
        Duration::from_millis(150)
    );
    assert_eq!(
        parse_duration("3s", Duration::from_secs(1)),
        Duration::from_secs(3)
    );
    assert_eq!(
        parse_duration("2m", Duration::from_secs(1)),
        Duration::from_secs(120)
    );
    assert_eq!(
        parse_duration("1h", Duration::from_secs(1)),
        Duration::from_secs(3600)
    );
}

#[test]
fn local_syslog_mode_detected_only_for_syslog_without_server() {
    let mut cfg = LoggerSinkConfig {
        name: "syslog".to_string(),
        format: "rfc5424".to_string(),
        protocol: "udp".to_string(),
        server: "".to_string(),
        write_timeout: "1s".to_string(),
        connect_timeout: "1s".to_string(),
        tag: "opensnitchd".to_string(),
        workers: 1,
        max_connect_attempts: 1,
    };

    assert!(is_local_syslog_mode(&cfg));

    cfg.server = "127.0.0.1:514".to_string();
    assert!(!is_local_syslog_mode(&cfg));

    cfg.name = "remote".to_string();
    cfg.server.clear();
    assert!(!is_local_syslog_mode(&cfg));
}

#[test]
fn formatter_json_contains_expected_fields() {
    let payload = format_message("json", "opensnitchd", &sample_connection(), Some(&sample_rule()));
    assert!(payload.contains("\"protocol\":\"tcp\""));
    assert!(payload.contains("\"dst_ip\":\"1.1.1.1\""));
    assert!(payload.contains("\"rule\":"));
}

#[test]
fn formatter_csv_contains_expected_columns() {
    let payload = format_message("csv", "opensnitchd", &sample_connection(), Some(&sample_rule()));
    assert!(payload.contains(",tcp,"));
    assert!(payload.contains(",1.1.1.1,"));
    assert!(payload.contains("allow-test"));
    assert!(payload.ends_with('\n'));
}

#[test]
fn formatter_rfc5424_has_expected_prefix() {
    let payload = format_message(
        "rfc5424",
        "opensnitchd",
        &sample_connection(),
        Some(&sample_rule()),
    );
    assert!(payload.starts_with("<14>1 "));
    assert!(payload.contains("protocol=tcp"));
}

#[test]
fn formatter_rfc3164_has_expected_prefix() {
    let payload = format_message(
        "rfc3164",
        "opensnitchd",
        &sample_connection(),
        Some(&sample_rule()),
    );
    assert!(payload.starts_with("<14>"));
    assert!(payload.contains(" opensnitchd: proto=tcp"));
}

#[test]
fn udp_worker_delivers_payload() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver udp socket");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set udp read timeout");
    let addr = receiver.local_addr().expect("resolve udp receiver addr");

    let cfg = LoggerSinkConfig {
        name: "remote".to_string(),
        format: "json".to_string(),
        protocol: "udp".to_string(),
        server: addr.to_string(),
        write_timeout: "1s".to_string(),
        connect_timeout: "1s".to_string(),
        tag: "opensnitchd".to_string(),
        workers: 1,
        max_connect_attempts: 1,
    };

    let (tx, rx) = mpsc::sync_channel::<String>(8);
    let handle = thread::spawn(move || run_sink_worker(cfg, rx));

    tx.send("udp-test-payload\n".to_string())
        .expect("send udp test payload");
    drop(tx);

    let mut buf = [0_u8; 2048];
    let (len, _src) = receiver.recv_from(&mut buf).expect("receive udp payload");
    let msg = String::from_utf8_lossy(&buf[..len]);
    assert!(msg.contains("udp-test-payload"));

    handle.join().expect("join udp worker");
}

#[test]
fn tcp_worker_delivers_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    listener
        .set_nonblocking(false)
        .expect("set blocking tcp listener");
    let addr = listener.local_addr().expect("resolve tcp listener addr");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept tcp client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set tcp read timeout");
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out);
        String::from_utf8_lossy(&out).to_string()
    });

    let cfg = LoggerSinkConfig {
        name: "remote".to_string(),
        format: "json".to_string(),
        protocol: "tcp".to_string(),
        server: addr.to_string(),
        write_timeout: "1s".to_string(),
        connect_timeout: "1s".to_string(),
        tag: "opensnitchd".to_string(),
        workers: 1,
        max_connect_attempts: 2,
    };

    let (tx, rx) = mpsc::sync_channel::<String>(8);
    let worker = thread::spawn(move || run_sink_worker(cfg, rx));

    tx.send("tcp-test-payload\n".to_string())
        .expect("send tcp test payload");
    drop(tx);

    worker.join().expect("join tcp worker");
    let received = server.join().expect("join tcp server");
    assert!(received.contains("tcp-test-payload"));
}

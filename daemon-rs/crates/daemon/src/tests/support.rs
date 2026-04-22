#![cfg(test)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Once},
    thread::JoinHandle,
    time::Duration,
};

use crate::utils::time_nonce::unique_name;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, reload};

/// Runs once, automatically, when the test binary loads — before any test starts.
/// Stops any conflicting opensnitchd/opensnitch-ui instances (systemd units and
/// standalone processes) so they cannot hold resources (nfqueue, gRPC socket, etc.)
/// that would cause test failures when running `cargo test` directly.
#[ctor::ctor]
fn test_suite_init() {
    stop_conflicting_services();
}

fn stop_conflicting_services() {
    use std::process::Stdio;
    let services = ["opensnitchd-rs", "opensnitchd", "opensnitch-ui"];

    for service in &services {
        if service_is_active_system(service) {
            run_privileged("systemctl", &["stop", service]);
        }
        if service_is_active_user(service) {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "stop", service])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    for name in &["opensnitchd-rs", "opensnitchd"] {
        let running = std::process::Command::new("pgrep")
            .args(["-x", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if running {
            run_privileged("pkill", &["-x", name]);
        }
    }
    let _ = std::process::Command::new("pkill")
        .args(["-f", r"(^|[[:space:]/])opensnitch-ui([[:space:]]|$)"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Returns true only when `show --property=ActiveState` reports exactly
/// `ActiveState=active`.  More reliable than `is-active --quiet` which can
/// return exit 0 for units in edge-case states on some systemd versions.
fn service_is_active_system(service: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["show", "--property=ActiveState", service])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l == "ActiveState=active")
        })
        .unwrap_or(false)
}

fn service_is_active_user(service: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "show", "--property=ActiveState", service])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l == "ActiveState=active")
        })
        .unwrap_or(false)
}

/// Returns the best privilege-escalation tool:
/// - `None`           — already root, run directly.
/// - `Some("pkexec")` — desktop session + pkexec available (graphical dialog).
/// - `Some("sudo")`   — non-desktop or pkexec unavailable (non-interactive).
fn priv_cmd() -> Option<&'static str> {
    let is_root = std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if is_root {
        return None;
    }
    let in_desktop = std::env::var("DISPLAY").map_or(false, |v| !v.is_empty())
        || std::env::var("WAYLAND_DISPLAY").map_or(false, |v| !v.is_empty());
    if in_desktop
        && std::process::Command::new("which")
            .arg("pkexec")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    {
        return Some("pkexec");
    }
    Some("sudo")
}

/// Run `program args` silently with the appropriate privilege escalation.
/// Never blocks on a terminal password prompt.
fn run_privileged(program: &str, args: &[&str]) {
    use std::process::Stdio;
    match priv_cmd() {
        None => {
            let _ = std::process::Command::new(program)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        Some("pkexec") => {
            let mut full: Vec<&str> = vec![program];
            full.extend_from_slice(args);
            let code = std::process::Command::new("pkexec")
                .args(&full)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.code().unwrap_or(-1))
                .unwrap_or(-1);
            // Fall back to sudo only when pkexec itself failed to dispatch:
            // 126 = polkit auth not obtained, 127 = binary not found.
            if code == 126 || code == 127 {
                let mut sudo_args = vec!["-n", "--", program];
                sudo_args.extend_from_slice(args);
                let _ = std::process::Command::new("sudo")
                    .args(&sudo_args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        Some(tool) => {
            let mut cmd_args = vec!["-n", "--", program];
            cmd_args.extend_from_slice(args);
            let _ = std::process::Command::new(tool)
                .args(&cmd_args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

pub(crate) struct TestDir {
    pub(crate) path: PathBuf,
}

pub(crate) fn temp_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(unique_name(prefix))
}

pub(crate) fn ensure_dir(path: &Path) {
    fs::create_dir_all(path).expect("create temp dir");
}

pub(crate) fn remove_dir_if_exists(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

pub(crate) fn write_text(path: &Path, content: &str) {
    fs::write(path, content).expect("write test file");
}

pub(crate) fn write_bytes(path: &Path, content: &[u8]) {
    fs::write(path, content).expect("write test file");
}

pub(crate) fn read_text(path: &Path) -> String {
    fs::read_to_string(path).expect("read test file")
}

pub(crate) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(crate) async fn remove_file_async(path: &Path, error_context: &str) {
    tokio::fs::remove_file(path).await.expect(error_context);
}

pub(crate) fn assert_storage_event(
    rx: &mut tokio::sync::broadcast::Receiver<crate::services::storage::StorageEvent>,
    recv_label: &str,
    domain: &'static str,
    operation: crate::services::storage::StorageOperation,
    path: &Path,
) {
    assert_eq!(
        rx.try_recv().expect(recv_label),
        crate::services::storage::StorageEvent {
            domain,
            operation,
            path: path.to_path_buf(),
        }
    );
}

pub(crate) fn assert_storage_event_empty(
    rx: &mut tokio::sync::broadcast::Receiver<crate::services::storage::StorageEvent>,
) {
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let path = temp_path(prefix);
        ensure_dir(&path);
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        remove_dir_if_exists(&self.path);
    }
}

pub(crate) fn init_test_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,opensnitchd_rs=debug"));
        let (filter_layer, handle) = reload::Layer::new(filter);
        let _ = crate::logging::LOG_FILTER_HANDLE.set(handle);

        let _ = tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .without_time()
                    .with_target(false)
                    .with_test_writer(),
            )
            .try_init();
    });
}

pub(crate) struct HttpResponseFixture {
    pub(crate) status: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl HttpResponseFixture {
    pub(crate) fn new(
        status: impl Into<String>,
        headers: Vec<(String, String)>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            status: status.into(),
            headers,
            body: body.into(),
        }
    }
}

pub(crate) struct HttpFixture {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<JoinHandle<()>>,
}

impl HttpFixture {
    pub(crate) fn start(responses: Vec<HttpResponseFixture>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
        listener
            .set_nonblocking(false)
            .expect("configure HTTP fixture listener");
        let addr = listener.local_addr().expect("resolve HTTP fixture addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);

        let handle = std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept HTTP fixture connection");
                let request = read_http_request(&mut stream);
                captured
                    .lock()
                    .expect("lock HTTP fixture request log")
                    .push(request);

                let mut raw = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    raw.push_str(&format!("{}: {}\r\n", name, value));
                }
                raw.push_str("\r\n");

                stream
                    .write_all(raw.as_bytes())
                    .expect("write HTTP fixture headers");
                if !response.body.is_empty() {
                    stream
                        .write_all(&response.body)
                        .expect("write HTTP fixture body");
                }
                stream.flush().expect("flush HTTP fixture response");
            }
        });

        Self {
            addr,
            requests,
            handle: Some(handle),
        }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("lock HTTP fixture request log")
            .clone()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            for _ in 0..4 {
                if handle.is_finished() {
                    break;
                }
                let _ = TcpStream::connect(self.addr);
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = handle.join();
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("configure HTTP fixture stream timeout");
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => panic!("read HTTP fixture request: {err}"),
        }
    }

    String::from_utf8_lossy(&buffer).into_owned()
}

use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use nix::libc;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn opt_in_enabled() -> bool {
    if is_root() {
        return true;
    }
    if std::env::var("OPENSNITCH_RUN_PRIVILEGED_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return true;
    }
    if std::env::var("OPENSNITCH_RUN_PRIVILEDGED_TESTS")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return true;
    }
    false
}

fn daemon_rs_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cargo_target_dir(root: &PathBuf) -> PathBuf {
    std::env::var_os("OPENSNITCH_CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"))
}

fn run_status(cmd: &mut Command, context: &str) {
    let status = cmd.status().unwrap_or_else(|err| {
        panic!("{context}: failed to spawn command: {err}");
    });
    assert!(status.success(), "{context}: command failed with status {status}");
}

fn command_success(cmd: &mut Command) -> bool {
    cmd.status().map(|status| status.success()).unwrap_or(false)
}

fn command_exists(bin: &str) -> bool {
    command_success(
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {bin} >/dev/null 2>&1")),
    )
}

fn run_shell(script: &str) -> bool {
    command_success(Command::new("bash").arg("-lc").arg(script))
}

fn map_dump_keys(id: u32) -> Vec<Vec<u8>> {
    #[cfg(feature = "aya-ebpf")]
    {
        use aya::maps::{HashMap as AyaHashMap, Map, MapData};
        if let Ok(md) = MapData::from_id(id) {
            // Try IPv4 key size (12 bytes).
            if let Ok(m) = AyaHashMap::<_, [u8; 12], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().flatten().map(|k| k.to_vec()).collect();
            }
        }
        if let Ok(md) = MapData::from_id(id) {
            // Try IPv6 key size (36 bytes).
            if let Ok(m) = AyaHashMap::<_, [u8; 36], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().flatten().map(|k| k.to_vec()).collect();
            }
        }
        return Vec::new();
    }

    #[cfg(not(feature = "aya-ebpf"))]
    Vec::new()
}

fn has_udp_dport(keys: &[Vec<u8>], dport_be: [u8; 2]) -> bool {
    keys.iter()
        .any(|key| key.len() >= 8 && key[6] == dport_be[0] && key[7] == dport_be[1])
}

fn try_exercise_ipip_tunnel() -> bool {
    if !command_exists("ip") {
        return false;
    }

    run_shell(
        "set -e; \
        ip link del osns-ipip-smoke >/dev/null 2>&1 || true; \
        ip tunnel add osns-ipip-smoke mode ipip local 127.0.0.1 remote 127.0.0.1 ttl 64; \
        ip addr add 10.250.42.1/30 dev osns-ipip-smoke >/dev/null 2>&1 || true; \
        ip link set osns-ipip-smoke up; \
        ping -n -c 1 -W 1 -I osns-ipip-smoke 10.250.42.2 >/dev/null 2>&1"
    )
}

fn try_exercise_vxlan_tunnel() -> bool {
    if !command_exists("ip") {
        return false;
    }

    run_shell(
        "set -e; \
        ip link del osns-vxlan-smoke >/dev/null 2>&1 || true; \
        ip -6 link add osns-vxlan-smoke type vxlan id 42 dev lo local ::1 dstport 4789 nolearning; \
        ip link set osns-vxlan-smoke up; \
        ip -6 addr add fd00:42::1/64 dev osns-vxlan-smoke >/dev/null 2>&1 || true; \
        bridge fdb append 00:00:00:00:00:00 dev osns-vxlan-smoke dst ::1 >/dev/null 2>&1 || true; \
        ping -6 -n -c 1 -W 1 -I osns-vxlan-smoke fd00:42::2 >/dev/null 2>&1"
    )
}

fn cleanup_tunnel_links() {
    let _ = run_shell("ip link del osns-vxlan-smoke >/dev/null 2>&1 || true");
    let _ = run_shell("ip link del osns-ipip-smoke >/dev/null 2>&1 || true");
}

fn resolve_built_rust_ebpf_obj(target_dir: &PathBuf) -> Option<PathBuf> {
    let release_so = target_dir.join("bpfel-unknown-none/release/libopensnitch_ebpf.so");
    let debug_so = target_dir.join("bpfel-unknown-none/debug/libopensnitch_ebpf.so");
    if release_so.exists() {
        Some(release_so)
    } else if debug_so.exists() {
        Some(debug_so)
    } else {
        None
    }
}

fn map_id_by_name(name: &str) -> Option<u32> {
    #[cfg(feature = "aya-ebpf")]
    {
        return aya::maps::loaded_maps()
            .flatten()
            .find(|info| info.name_as_str() == Some(name))
            .map(|info| info.id());
    }

    #[cfg(not(feature = "aya-ebpf"))]
    {
        let _ = name;
        None
    }
}

fn map_has_entries(id: u32) -> bool {
    #[cfg(feature = "aya-ebpf")]
    {
        use aya::maps::{HashMap as AyaHashMap, Map, MapData};
        if let Ok(md) = MapData::from_id(id) {
            if let Ok(m) = AyaHashMap::<_, [u8; 12], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().next().is_some();
            }
        }
        if let Ok(md) = MapData::from_id(id) {
            if let Ok(m) = AyaHashMap::<_, [u8; 36], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().next().is_some();
            }
        }
        return false;
    }

    #[cfg(not(feature = "aya-ebpf"))]
    {
        let _ = id;
        false
    }
}

#[test]
#[ignore = "requires root privileges and local kernel eBPF support"]
fn aya_conn_trace_smoke_reports_explicit_runtime_active() {
    if !opt_in_enabled() {
        return;
    }

    if !is_root() {
        panic!(
            "aya connection trace smoke requires elevated privileges; rerun using sudo/pkexec and OPENSNITCH_RUN_PRIVILEGED_TESTS=1"
        );
    }

    let daemon_root = daemon_rs_root();
    let target_dir = cargo_target_dir(&daemon_root);
    let daemon_bin = target_dir.join("release/opensnitchd-rs");
    run_status(
        Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("-p")
            .arg("opensnitchd-rs")
            .env("CARGO_TARGET_DIR", &target_dir)
            .current_dir(&daemon_root),
        "build opensnitchd-rs",
    );

    run_status(
        Command::new("cargo")
            .arg("+nightly")
            .arg("build")
            .arg("-p")
            .arg("opensnitch-ebpf")
            .arg("-Z")
            .arg("build-std=core")
            .arg("-Z")
            .arg("build-std-features=compiler-builtins-mem")
            .arg("--target")
            .arg("bpfel-unknown-none")
            .arg("--release")
            .env("CARGO_TARGET_DIR", &target_dir)
            .current_dir(&daemon_root),
        "build opensnitch-ebpf",
    );

    let rust_obj = resolve_built_rust_ebpf_obj(&target_dir)
        .unwrap_or_else(|| target_dir.join("bpfel-unknown-none/release/libopensnitch_ebpf.so"));
    assert!(
        rust_obj.exists(),
        "missing rust eBPF object {}; build it first with the privileged bpf build path",
        rust_obj.display()
    );

    let _ = fs::create_dir_all(target_dir.join("bpfel-unknown-none/release"));
    let normalized_obj = target_dir.join("bpfel-unknown-none/release/opensnitch-ebpf");
    fs::copy(&rust_obj, &normalized_obj)
        .unwrap_or_else(|err| panic!("copy rust eBPF object to {} failed: {err}", normalized_obj.display()));

    fs::create_dir_all("/etc/opensnitchd").expect("create /etc/opensnitchd");
    fs::copy(&rust_obj, "/etc/opensnitchd/opensnitch-ebpf")
        .expect("copy /etc/opensnitchd/opensnitch-ebpf");

    let _ = Command::new("pkill").arg("-x").arg("opensnitchd-rs").status();

    let _ = fs::remove_file("/sys/fs/bpf/opensnitch-rs/tcpMap");

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let smoke_log = std::env::temp_dir().join(format!("opensnitch-aya-conn-trace-test-{unique}.log"));

    let mut daemon = Command::new("timeout")
        .arg("24s")
        .arg(&daemon_bin)
        .env("OPENSNITCH_EBPF_PIN_DOMAIN", "aya")
        .env("RUST_LOG", "debug")
        .stdout(
            fs::File::create(&smoke_log)
                .unwrap_or_else(|err| panic!("create {} failed: {err}", smoke_log.display())),
        )
        .stderr(
            fs::File::options()
                .append(true)
                .open(&smoke_log)
                .unwrap_or_else(|err| panic!("open {} failed: {err}", smoke_log.display())),
        )
        .spawn()
        .expect("start opensnitchd-rs smoke daemon");

    thread::sleep(Duration::from_secs(2));

    let mut http_server = Command::new("python3")
        .args(["-m", "http.server", "38080", "--bind", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start local http server");

    thread::sleep(Duration::from_millis(500));

    for _ in 0..40 {
        let _ = Command::new("python3")
            .arg("-c")
            .arg(
                "import socket; s=socket.create_connection(('127.0.0.1',38080),2); s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); s.recv(64); s.close(); u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.sendto(b'x',('127.0.0.1',53535)); u.close()",
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        thread::sleep(Duration::from_millis(100));
    }

    // Exercise tunnel-specific paths when the host supports creating test links.
    let ipip_ready = try_exercise_ipip_tunnel();
    let vxlan_ready = try_exercise_vxlan_tunnel();
    thread::sleep(Duration::from_millis(500));

    let tcp_id = map_id_by_name("tcpMap");
    let udp_id = map_id_by_name("udpMap");
    let udpv6_id = map_id_by_name("udpv6Map");

    let tcp_has_entries = tcp_id.is_some_and(map_has_entries);
    let udp_has_entries = udp_id.is_some_and(map_has_entries);

    let vxlan_port_be = [0x12u8, 0xb5u8];
    let udp_has_vxlan_dport = udp_id
        .map(map_dump_keys)
        .is_some_and(|keys| has_udp_dport(&keys, vxlan_port_be));
    let udpv6_has_vxlan_dport = udpv6_id
        .map(map_dump_keys)
        .is_some_and(|keys| has_udp_dport(&keys, vxlan_port_be));

    cleanup_tunnel_links();

    let _ = http_server.kill();
    let _ = http_server.wait();
    let _ = daemon.wait();

    let log = fs::read_to_string(&smoke_log)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", smoke_log.display()));

    assert!(
        log.contains("worker=\"ebpf-conn\""),
        "expected ebpf-conn worker trace in log {}",
        smoke_log.display()
    );
    assert!(
        log.contains("explicit connection eBPF runtime active"),
        "expected explicit Aya connection runtime activation in log {}",
        smoke_log.display()
    );
    assert!(
        tcp_has_entries || udp_has_entries,
        "expected tcpMap or udpMap to contain entries after traffic generation"
    );

    if ipip_ready || vxlan_ready {
        assert!(
            udp_has_vxlan_dport || udpv6_has_vxlan_dport,
            "expected udpMap/udpv6Map to contain VXLAN dport 4789 entries after tunnel traffic"
        );
    } else {
        eprintln!(
            "skipping strict VXLAN/IP tunnel assertion because tunnel traffic could not be confirmed on this host"
        );
    }
}

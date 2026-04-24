use std::{
    fs,
    path::PathBuf,
    process::Command,
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
    assert!(
        status.success(),
        "{context}: command failed with status {status}"
    );
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

fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

fn map_dump_keys(id: u32) -> Vec<Vec<u8>> {
    #[cfg(feature = "aya-ebpf")]
    {
        use aya::maps::{HashMap as AyaHashMap, Map, MapData};
        if let Ok(md) = MapData::from_id(id) {
            if let Ok(m) = AyaHashMap::<_, [u8; 12], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().flatten().map(|k| k.to_vec()).collect();
            }
        }
        if let Ok(md) = MapData::from_id(id) {
            if let Ok(m) = AyaHashMap::<_, [u8; 36], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().flatten().map(|k| k.to_vec()).collect();
            }
        }
        return Vec::new();
    }

    #[cfg(not(feature = "aya-ebpf"))]
    {
        let _ = id;
        Vec::new()
    }
}

fn map_entry_count(id: u32) -> usize {
    #[cfg(feature = "aya-ebpf")]
    {
        use aya::maps::{HashMap as AyaHashMap, Map, MapData};
        if let Ok(md) = MapData::from_id(id) {
            if let Ok(m) = AyaHashMap::<_, [u8; 12], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().count();
            }
        }
        if let Ok(md) = MapData::from_id(id) {
            if let Ok(m) = AyaHashMap::<_, [u8; 36], [u8; 16]>::try_from(Map::HashMap(md)) {
                return m.keys().count();
            }
        }
        return 0;
    }

    #[cfg(not(feature = "aya-ebpf"))]
    {
        let _ = id;
        0
    }
}

fn has_udp_dport(keys: &[Vec<u8>], dport_be: [u8; 2]) -> bool {
    keys.iter()
        .any(|key| key.len() >= 8 && key[6] == dport_be[0] && key[7] == dport_be[1])
}

fn run_shell_output(script: &str) -> (bool, String) {
    match Command::new("bash").arg("-lc").arg(script).output() {
        Ok(out) => {
            let mut msg = String::new();
            if !out.stdout.is_empty() {
                msg.push_str(&String::from_utf8_lossy(&out.stdout));
            }
            if !out.stderr.is_empty() {
                msg.push_str(&String::from_utf8_lossy(&out.stderr));
            }
            (out.status.success(), msg)
        }
        Err(err) => (false, format!("spawn failed: {err}")),
    }
}

fn try_exercise_ipip_tunnel() -> (bool, String) {
    if !command_exists("ip") {
        return (false, "ip tool unavailable".to_string());
    }

    run_shell_output(
        "set -e; \
        ip link del osns-ipip-smoke >/dev/null 2>&1 || true; \
        ip tunnel add osns-ipip-smoke mode ipip local 127.0.0.1 remote 127.0.0.1 ttl 64; \
        ip addr add 10.250.42.1/30 dev osns-ipip-smoke >/dev/null 2>&1 || true; \
        ip link set osns-ipip-smoke up; \
        ping -n -c 1 -W 1 -I osns-ipip-smoke 10.250.42.2 >/dev/null 2>&1",
    )
}

fn try_exercise_vxlan_tunnel() -> (bool, String) {
    if !command_exists("ip") {
        return (false, "ip tool unavailable".to_string());
    }

    run_shell_output(
        "set -e; \
        ip link del osns-vxlan-smoke >/dev/null 2>&1 || true; \
        ip -6 link add osns-vxlan-smoke type vxlan id 42 dev lo local ::1 dstport 4789 nolearning; \
        ip link set osns-vxlan-smoke up; \
        ip -6 addr add fd00:42::1/64 dev osns-vxlan-smoke >/dev/null 2>&1 || true; \
        bridge fdb append 00:00:00:00:00:00 dev osns-vxlan-smoke dst ::1 >/dev/null 2>&1 || true; \
        ping -6 -n -c 1 -W 1 -I osns-vxlan-smoke fd00:42::2 >/dev/null 2>&1",
    )
}

fn cleanup_tunnel_links() {
    let _ = Command::new("bash")
        .arg("-lc")
        .arg("ip link del osns-vxlan-smoke >/dev/null 2>&1 || true")
        .status();
    let _ = Command::new("bash")
        .arg("-lc")
        .arg("ip link del osns-ipip-smoke >/dev/null 2>&1 || true")
        .status();
}

#[test]
#[ignore = "requires root privileges and local kernel eBPF support"]
fn aya_tunnel_trace_smoke_reports_tunnel_probe_activity() {
    if !opt_in_enabled() {
        return;
    }

    if !is_root() {
        panic!(
            "aya tunnel trace smoke requires elevated privileges; rerun using sudo/pkexec and OPENSNITCH_RUN_PRIVILEGED_TESTS=1"
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
    fs::copy(&rust_obj, &normalized_obj).unwrap_or_else(|err| {
        panic!(
            "copy rust eBPF object to {} failed: {err}",
            normalized_obj.display()
        )
    });

    fs::create_dir_all("/etc/opensnitchd").expect("create /etc/opensnitchd");
    fs::copy(&rust_obj, "/etc/opensnitchd/opensnitch-ebpf")
        .expect("copy /etc/opensnitchd/opensnitch-ebpf");

    let _ = Command::new("pkill")
        .arg("-x")
        .arg("opensnitchd-rs")
        .status();

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let smoke_log =
        std::env::temp_dir().join(format!("opensnitch-aya-tunnel-trace-test-{unique}.log"));

    let mut daemon = Command::new("timeout")
        .args(["--kill-after=2s", "20s"])
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

    thread::sleep(Duration::from_secs(3));

    let udp_before = map_id_by_name("udpMap").map(map_entry_count).unwrap_or(0);
    let udpv6_before = map_id_by_name("udpv6Map").map(map_entry_count).unwrap_or(0);

    let (ipip_ok, ipip_diag) = try_exercise_ipip_tunnel();
    let (vxlan_ok, vxlan_diag) = try_exercise_vxlan_tunnel();
    thread::sleep(Duration::from_millis(500));

    let udp_id = map_id_by_name("udpMap");
    let udpv6_id = map_id_by_name("udpv6Map");

    let udp_after = udp_id.map(map_entry_count).unwrap_or(0);
    let udpv6_after = udpv6_id.map(map_entry_count).unwrap_or(0);

    let vxlan_port_be = [0x12u8, 0xb5u8];
    let udp_has_vxlan_dport = udp_id
        .map(map_dump_keys)
        .is_some_and(|keys| has_udp_dport(&keys, vxlan_port_be));
    let udpv6_has_vxlan_dport = udpv6_id
        .map(map_dump_keys)
        .is_some_and(|keys| has_udp_dport(&keys, vxlan_port_be));
    let ipip_evidence = udp_after > udp_before || udpv6_after > udpv6_before;

    cleanup_tunnel_links();

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

    if ipip_ok || vxlan_ok {
        assert!(
            udp_has_vxlan_dport || udpv6_has_vxlan_dport || ipip_evidence,
            "expected tunnel probe evidence after successful setup; ipip_ok={ipip_ok}, vxlan_ok={vxlan_ok}, udp_before={udp_before}, udp_after={udp_after}, udpv6_before={udpv6_before}, udpv6_after={udpv6_after}, ipip_diag={ipip_diag:?}, vxlan_diag={vxlan_diag:?}"
        );
    } else {
        eprintln!(
            "skipping strict tunnel evidence assertion because setup did not succeed: ipip={ipip_diag:?}; vxlan={vxlan_diag:?}"
        );
    }
}

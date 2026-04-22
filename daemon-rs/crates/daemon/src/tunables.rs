use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{OnceLock, RwLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tracing::warn;

pub use crate::models::effective_tunables::{NfqueueOverloadPolicy, RuntimeTunables};
use crate::models::runtime_tunables::RawRuntimeTunables;
use crate::utils::name_parsing::normalized_name;
use crate::utils::systemd_notify::{NotifyState, notify};

const MIN_CONNECT_WORKERS: usize = 1;
const MAX_CONNECT_WORKERS: usize = 256;
const MIN_CONNECT_QUEUE_CAPACITY: usize = 16;
const MAX_CONNECT_QUEUE_CAPACITY: usize = 8192;
const MIN_CONNECT_DISPATCH_BATCH: usize = 1;
const MAX_CONNECT_DISPATCH_BATCH: usize = 256;
const MIN_KERNEL_INGRESS_DISPATCH_BATCH: usize = 8;
const MAX_KERNEL_INGRESS_DISPATCH_BATCH: usize = 256;
const MIN_KERNEL_QUEUE_CAPACITY: usize = 64;
const MAX_KERNEL_QUEUE_CAPACITY: usize = 16384;
const MIN_EBPF_PRUNE_THRESHOLD_PERCENT: usize = 50;
const MAX_EBPF_PRUNE_THRESHOLD_PERCENT: usize = 99;
const MIN_EBPF_PRUNE_TARGET_PERCENT: usize = 10;
const MAX_EBPF_PRUNE_TARGET_PERCENT: usize = 90;
const MIN_LRU_CACHE_CAPACITY: usize = 1_024;
const MAX_LRU_CACHE_CAPACITY: usize = 16_000_000;
const MIN_RING_BUFFER_CAPACITY: usize = 1;
const MAX_RING_BUFFER_CAPACITY: usize = 1_000_000;
const MIN_NETLINK_DELAY_MS: usize = 100;
const MAX_NETLINK_DELAY_MS: usize = 10_000;

static EFFECTIVE_TUNABLES: OnceLock<RwLock<RuntimeTunables>> = OnceLock::new();

impl NfqueueOverloadPolicy {
    fn parse(raw: &str) -> Option<Self> {
        match normalized_name(raw).as_str() {
            "fail-open" | "fail_open" | "default-action" => Some(Self::FailOpen),
            "drop-fast" | "drop_fast" | "deny-fast" | "deny_fast" => Some(Self::DropFast),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailOpen => "fail-open",
            Self::DropFast => "drop-fast",
        }
    }
}

impl Default for RuntimeTunables {
    fn default() -> Self {
        Self {
            max_concurrent_connect_attempts: 32,
            connect_worker_queue_capacity: 64,
            connect_dispatch_batch_size: 64,
            kernel_ingress_dispatch_batch_size: 32,
            kernel_dns_dispatch_batch_size: 32,
            kernel_process_dispatch_batch_size: 32,
            kernel_firewall_dispatch_batch_size: 32,
            kernel_dns_queue_capacity: 512,
            kernel_process_queue_capacity: 512,
            kernel_firewall_queue_capacity: 128,
            nfqueue_overload_policy: NfqueueOverloadPolicy::FailOpen,
            netlink_fallback_retry_delay_ms: 800,
            netlink_recovery_poll_interval_ms: 800,
            ebpf_map_prune_enabled: true,
            ebpf_map_prune_threshold_percent: 80,
            ebpf_map_prune_target_percent: 50,
            // AdGuard Home uses large DNS caches by default; keep this generous but tunable.
            dns_lru_cache_capacity: 4_000_000,
            process_info_cache_capacity: 131_072,
            pid_inode_cache_capacity: 262_144,
            pid_inode_key_cache_capacity: 262_144,
            stats_event_ring_capacity: 250,
            alert_overflow_ring_capacity: 32,
        }
    }
}

impl RuntimeTunables {
    pub fn publish_global(self) {
        if let Some(global) = EFFECTIVE_TUNABLES.get() {
            if let Ok(mut current) = global.write() {
                *current = self;
            }
            return;
        }

        let _ = EFFECTIVE_TUNABLES.set(RwLock::new(self));
    }

    pub fn global() -> Self {
        EFFECTIVE_TUNABLES
            .get()
            .and_then(|global| global.read().ok().map(|current| *current))
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn reload_global() -> (Self, String) {
        let (tunables, source) = Self::load_effective();
        tunables.publish_global();
        (tunables, source)
    }

    pub fn load_effective() -> (Self, String) {
        let mut tunables = Self::default();
        let mut source_parts = vec!["defaults(conservative)".to_string()];

        if let Some(path) = Self::resolve_optin_tunables_path() {
            match Self::load_raw_tunables(&path) {
                Ok(raw) => {
                    tunables = tunables.apply_raw(raw);
                    source_parts.push(format!("file={}", path.display()));
                }
                Err(err) => {
                    warn!(path = %path.display(), "failed to load tunables file: {err}");
                }
            }
        }

        let env_override_count = tunables.apply_env_overrides();
        if env_override_count > 0 {
            source_parts.push(format!("env_overrides={env_override_count}"));
        }

        (tunables, source_parts.join(", "))
    }

    fn apply_raw(mut self, raw: RawRuntimeTunables) -> Self {
        if let Some(value) = raw.max_concurrent_connect_attempts {
            self.max_concurrent_connect_attempts =
                Self::clamp(value, MIN_CONNECT_WORKERS, MAX_CONNECT_WORKERS);
        }
        if let Some(value) = raw.connect_worker_queue_capacity {
            self.connect_worker_queue_capacity = Self::clamp(
                value,
                MIN_CONNECT_QUEUE_CAPACITY,
                MAX_CONNECT_QUEUE_CAPACITY,
            );
        }
        if let Some(value) = raw.connect_dispatch_batch_size {
            self.connect_dispatch_batch_size = Self::clamp(
                value,
                MIN_CONNECT_DISPATCH_BATCH,
                MAX_CONNECT_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_ingress_dispatch_batch_size {
            self.kernel_ingress_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_dns_dispatch_batch_size {
            self.kernel_dns_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_process_dispatch_batch_size {
            self.kernel_process_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_firewall_dispatch_batch_size {
            self.kernel_firewall_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
        }
        if let Some(value) = raw.kernel_dns_queue_capacity {
            self.kernel_dns_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
        }
        if let Some(value) = raw.kernel_process_queue_capacity {
            self.kernel_process_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
        }
        if let Some(value) = raw.kernel_firewall_queue_capacity {
            self.kernel_firewall_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
        }
        if let Some(value) = raw.nfqueue_overload_policy {
            if let Some(policy) = NfqueueOverloadPolicy::parse(&value) {
                self.nfqueue_overload_policy = policy;
            } else {
                warn!(
                    value = %value,
                    "invalid nfqueue_overload_policy in tunables file ignored"
                );
            }
        }
        if let Some(value) = raw.netlink_fallback_retry_delay_ms {
            self.netlink_fallback_retry_delay_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
        }
        if let Some(value) = raw.netlink_recovery_poll_interval_ms {
            self.netlink_recovery_poll_interval_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
        }
        if let Some(value) = raw.ebpf_map_prune_enabled {
            self.ebpf_map_prune_enabled = value;
        }
        if let Some(value) = raw.ebpf_map_prune_threshold_percent {
            self.ebpf_map_prune_threshold_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_THRESHOLD_PERCENT,
                MAX_EBPF_PRUNE_THRESHOLD_PERCENT,
            );
        }
        if let Some(value) = raw.ebpf_map_prune_target_percent {
            self.ebpf_map_prune_target_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_TARGET_PERCENT,
                MAX_EBPF_PRUNE_TARGET_PERCENT,
            );
        }
        if let Some(value) = raw.dns_lru_cache_capacity {
            self.dns_lru_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.process_info_cache_capacity {
            self.process_info_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.pid_inode_cache_capacity {
            self.pid_inode_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.pid_inode_key_cache_capacity {
            self.pid_inode_key_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
        }
        if let Some(value) = raw.stats_event_ring_capacity {
            self.stats_event_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
        }
        if let Some(value) = raw.alert_overflow_ring_capacity {
            self.alert_overflow_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
        }
        self
    }

    fn apply_env_overrides(&mut self) -> usize {
        let mut count = 0;

        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_MAX_CONCURRENT_CONNECT_ATTEMPTS")
        {
            self.max_concurrent_connect_attempts =
                Self::clamp(value, MIN_CONNECT_WORKERS, MAX_CONNECT_WORKERS);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_CONNECT_WORKER_QUEUE_CAPACITY")
        {
            self.connect_worker_queue_capacity = Self::clamp(
                value,
                MIN_CONNECT_QUEUE_CAPACITY,
                MAX_CONNECT_QUEUE_CAPACITY,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_CONNECT_DISPATCH_BATCH_SIZE") {
            self.connect_dispatch_batch_size = Self::clamp(
                value,
                MIN_CONNECT_DISPATCH_BATCH,
                MAX_CONNECT_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_INGRESS_DISPATCH_BATCH_SIZE")
        {
            self.kernel_ingress_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_DNS_DISPATCH_BATCH_SIZE")
        {
            self.kernel_dns_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_PROCESS_DISPATCH_BATCH_SIZE")
        {
            self.kernel_process_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_FIREWALL_DISPATCH_BATCH_SIZE")
        {
            self.kernel_firewall_dispatch_batch_size = Self::clamp(
                value,
                MIN_KERNEL_INGRESS_DISPATCH_BATCH,
                MAX_KERNEL_INGRESS_DISPATCH_BATCH,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_DNS_QUEUE_CAPACITY") {
            self.kernel_dns_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_PROCESS_QUEUE_CAPACITY")
        {
            self.kernel_process_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_KERNEL_FIREWALL_QUEUE_CAPACITY")
        {
            self.kernel_firewall_queue_capacity =
                Self::clamp(value, MIN_KERNEL_QUEUE_CAPACITY, MAX_KERNEL_QUEUE_CAPACITY);
            count += 1;
        }
        if let Some(raw) = std::env::var("OPENSNITCH_TUNE_NFQUEUE_OVERLOAD_POLICY").ok() {
            if let Some(policy) = NfqueueOverloadPolicy::parse(&raw) {
                self.nfqueue_overload_policy = policy;
                count += 1;
            } else {
                warn!(
                    name = "OPENSNITCH_TUNE_NFQUEUE_OVERLOAD_POLICY",
                    value = %raw,
                    "invalid tunable env override ignored"
                );
            }
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_NETLINK_FALLBACK_RETRY_DELAY_MS")
        {
            self.netlink_fallback_retry_delay_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_NETLINK_RECOVERY_POLL_INTERVAL_MS")
        {
            self.netlink_recovery_poll_interval_ms =
                Self::clamp(value, MIN_NETLINK_DELAY_MS, MAX_NETLINK_DELAY_MS);
            count += 1;
        }
        if let Some(value) = Self::parse_env_bool("OPENSNITCH_TUNE_EBPF_MAP_PRUNE_ENABLED") {
            self.ebpf_map_prune_enabled = value;
            count += 1;
        }
        if let Some(value) =
            Self::parse_env_usize("OPENSNITCH_TUNE_EBPF_MAP_PRUNE_THRESHOLD_PERCENT")
        {
            self.ebpf_map_prune_threshold_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_THRESHOLD_PERCENT,
                MAX_EBPF_PRUNE_THRESHOLD_PERCENT,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_EBPF_MAP_PRUNE_TARGET_PERCENT")
        {
            self.ebpf_map_prune_target_percent = Self::clamp(
                value,
                MIN_EBPF_PRUNE_TARGET_PERCENT,
                MAX_EBPF_PRUNE_TARGET_PERCENT,
            );
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_DNS_LRU_CACHE_CAPACITY") {
            self.dns_lru_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_PROCESS_INFO_CACHE_CAPACITY") {
            self.process_info_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_PID_INODE_CACHE_CAPACITY") {
            self.pid_inode_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_PID_INODE_KEY_CACHE_CAPACITY") {
            self.pid_inode_key_cache_capacity =
                Self::clamp(value, MIN_LRU_CACHE_CAPACITY, MAX_LRU_CACHE_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_STATS_EVENT_RING_CAPACITY") {
            self.stats_event_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
            count += 1;
        }
        if let Some(value) = Self::parse_env_usize("OPENSNITCH_TUNE_ALERT_OVERFLOW_RING_CAPACITY") {
            self.alert_overflow_ring_capacity =
                Self::clamp(value, MIN_RING_BUFFER_CAPACITY, MAX_RING_BUFFER_CAPACITY);
            count += 1;
        }

        count
    }
    pub fn maybe_autotune_on_startup() -> Option<String> {
        if cfg!(test) {
            return Some("skipped(test-build)".to_string());
        }

        if Self::env_flag("OPENSNITCH_AUTOTUNE_DISABLE") {
            return Some("skipped(disabled)".to_string());
        }

        let output_path = Self::resolve_tunables_output_path();
        if output_path.exists() {
            return Some(format!(
                "skipped(existing-tunables={})",
                output_path.display()
            ));
        }

        let marker_path = Self::resolve_autotune_marker_path(&output_path);
        if marker_path.exists() {
            return Some(format!(
                "skipped(existing-marker={})",
                marker_path.display()
            ));
        }

        if let Err(reason) = Self::check_autotune_preflight() {
            return Some(format!("skipped(preflight:{reason})"));
        }

        let timeout_secs = std::env::var("OPENSNITCH_AUTOTUNE_BOOTSTRAP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(240)
            .clamp(30, 1800);

        notify(NotifyState::Status(
            "Autotuning runtime tunables before daemon readiness...",
        ));

        match Self::run_autotune_command(&output_path, Duration::from_secs(timeout_secs)) {
            Ok(()) => {
                notify(NotifyState::Status(
                    "Autotune complete; continuing daemon startup...",
                ));
                if let Err(err) = Self::write_autotune_marker(&marker_path) {
                    warn!(path = %marker_path.display(), "autotune succeeded but marker write failed: {err}");
                }
                Some(format!("applied(output={})", output_path.display()))
            }
            Err(err) => Some(format!("failed({err})")),
        }
    }

    fn parse_env_usize(name: &str) -> Option<usize> {
        let raw = std::env::var(name).ok()?;
        match raw.trim().parse::<usize>() {
            Ok(value) => Some(value),
            Err(err) => {
                warn!(%name, value = %raw, "invalid tunable env override ignored: {err}");
                None
            }
        }
    }

    fn parse_env_bool(name: &str) -> Option<bool> {
        let raw = std::env::var(name).ok()?;
        match normalized_name(&raw).as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => {
                warn!(%name, value = %raw, "invalid tunable bool env override ignored");
                None
            }
        }
    }

    fn check_autotune_preflight() -> Result<(), String> {
        let logical_cores = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
            .max(1);
        let max_load_per_core = std::env::var("OPENSNITCH_AUTOTUNE_PREFLIGHT_MAX_LOAD_PER_CORE")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(0.60)
            .clamp(0.05, 4.0);
        let min_mem_available_mb = std::env::var("OPENSNITCH_AUTOTUNE_PREFLIGHT_MIN_MEM_MB")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(512)
            .clamp(64, 131_072);
        let min_idle_ratio = std::env::var("OPENSNITCH_AUTOTUNE_PREFLIGHT_MIN_CPU_IDLE_RATIO")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(0.40)
            .clamp(0.05, 0.95);
        let sample_ms = std::env::var("OPENSNITCH_AUTOTUNE_PREFLIGHT_CPU_SAMPLE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(700)
            .clamp(200, 5_000);

        let load1 = Self::read_loadavg_1m().map_err(|err| format!("loadavg:{err}"))?;
        let load_per_core = load1 / logical_cores as f64;
        if load_per_core > max_load_per_core {
            return Err(format!(
                "load-too-high(load_per_core={load_per_core:.2}>max={max_load_per_core:.2})"
            ));
        }

        let mem_available_mb =
            Self::read_mem_available_mb().map_err(|err| format!("meminfo:{err}"))?;
        if mem_available_mb < min_mem_available_mb {
            return Err(format!(
                "mem-too-low(available_mb={mem_available_mb}<min={min_mem_available_mb})"
            ));
        }

        let idle_ratio = Self::read_cpu_idle_ratio(Duration::from_millis(sample_ms))
            .map_err(|err| format!("cpu-idle:{err}"))?;
        if idle_ratio < min_idle_ratio {
            return Err(format!(
                "cpu-too-busy(idle_ratio={idle_ratio:.2}<min={min_idle_ratio:.2})"
            ));
        }

        Ok(())
    }

    fn read_loadavg_1m() -> Result<f64, String> {
        let raw = fs::read_to_string("/proc/loadavg").map_err(|err| err.to_string())?;
        let first = raw
            .split_whitespace()
            .next()
            .ok_or_else(|| "missing loadavg value".to_string())?;
        first
            .parse::<f64>()
            .map_err(|err| format!("invalid loadavg value: {err}"))
    }

    fn read_mem_available_mb() -> Result<u64, String> {
        let raw = fs::read_to_string("/proc/meminfo").map_err(|err| err.to_string())?;
        let line = raw
            .lines()
            .find(|line| line.starts_with("MemAvailable:"))
            .ok_or_else(|| "MemAvailable not found".to_string())?;
        let kb = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| "MemAvailable value missing".to_string())?
            .parse::<u64>()
            .map_err(|err| format!("invalid MemAvailable value: {err}"))?;
        Ok(kb / 1024)
    }

    fn read_cpu_idle_ratio(sample_window: Duration) -> Result<f64, String> {
        let (idle0, total0) = Self::read_cpu_stat_snapshot()?;
        thread::sleep(sample_window);
        let (idle1, total1) = Self::read_cpu_stat_snapshot()?;
        let delta_total = total1.saturating_sub(total0);
        if delta_total == 0 {
            return Err("zero cpu sample window".to_string());
        }
        let delta_idle = idle1.saturating_sub(idle0);
        Ok(delta_idle as f64 / delta_total as f64)
    }

    fn read_cpu_stat_snapshot() -> Result<(u64, u64), String> {
        let raw = fs::read_to_string("/proc/stat").map_err(|err| err.to_string())?;
        let cpu = raw
            .lines()
            .find(|line| line.starts_with("cpu "))
            .ok_or_else(|| "cpu aggregate line not found".to_string())?;
        let mut values = [0_u64; 8];
        let mut count = 0_usize;
        for token in cpu.split_whitespace().skip(1) {
            if count >= 8 { break; }
            if let Ok(v) = token.parse::<u64>() {
                values[count] = v;
                count += 1;
            }
        }
        if count < 5 {
            return Err("cpu aggregate line missing fields".to_string());
        }
        let idle = values[3].saturating_add(values[4]);
        let total = values.iter().sum::<u64>();
        Ok((idle, total))
    }

    fn run_autotune_command(output_path: &Path, timeout: Duration) -> Result<(), String> {
        let daemon_rs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut child = Command::new("cargo")
            .current_dir(&daemon_rs_dir)
            .args([
                "run",
                "--release",
                "-p",
                "tools",
                "--",
                "auto-tune-kernel-pressure-tunables",
            ])
            .env("OPENSNITCH_TUNABLES_OUTPUT", output_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("spawn failed: {err}"))?;

        let started = Instant::now();
        let mut last_extend = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
                if !status.success() {
                    return Err(format!("autotune exit status: {status}"));
                }
                if !output_path.exists() {
                    return Err(format!(
                        "autotune completed but output not found: {}",
                        output_path.display()
                    ));
                }
                return Ok(());
            }

            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("autotune timeout after {}s", timeout.as_secs()));
            }

            if last_extend.elapsed() >= Duration::from_secs(2) {
                notify(NotifyState::ExtendTimeout(Duration::from_secs(15)));
                last_extend = Instant::now();
            }

            thread::sleep(Duration::from_millis(200));
        }
    }

    fn write_autotune_marker(marker_path: &Path) -> std::io::Result<()> {
        if let Some(parent) = marker_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or_default();
        fs::write(marker_path, format!("autotune_completed_unix={now}\n"))
    }

    fn resolve_tunables_output_path() -> PathBuf {
        if let Some(path) = std::env::var_os("OPENSNITCH_TUNABLES_FILE").map(PathBuf::from) {
            return path;
        }

        let system_path = PathBuf::from("/etc/opensnitchd/tunables.json");
        if system_path.exists() {
            return system_path;
        }

        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("daemon-rs/data/tunables.json")
    }

    fn resolve_autotune_marker_path(output_path: &Path) -> PathBuf {
        if let Some(path) = std::env::var_os("OPENSNITCH_AUTOTUNE_MARKER_FILE").map(PathBuf::from) {
            return path;
        }

        let mut marker = output_path.to_path_buf();
        let base_name = output_path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tunables.json".to_string());
        marker.set_file_name(format!("{base_name}.autotune.done"));
        marker
    }

    fn env_flag(name: &str) -> bool {
        matches!(
            std::env::var(name).as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
        )
    }

    fn resolve_optin_tunables_path() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("OPENSNITCH_TUNABLES_FILE").map(PathBuf::from) {
            if path.exists() {
                return Some(path);
            }
            warn!(path = %path.display(), "OPENSNITCH_TUNABLES_FILE is set but path does not exist; ignoring");
            return None;
        }

        let system_path = PathBuf::from("/etc/opensnitchd/tunables.json");
        if system_path.exists() {
            return Some(system_path);
        }

        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("daemon-rs/data/tunables.json");
        if dev_path.exists() {
            return Some(dev_path);
        }

        None
    }

    fn load_raw_tunables(path: &Path) -> anyhow::Result<RawRuntimeTunables> {
        let raw_json = fs::read_to_string(path)?;
        Ok(serde_json::from_str::<RawRuntimeTunables>(&raw_json)?)
    }

    fn clamp(value: usize, min: usize, max: usize) -> usize {
        value.clamp(min, max)
    }
}

#[cfg(test)]
#[path = "tests/parsing/tunables.rs"]
mod tests;

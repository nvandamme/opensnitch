//! Kernel capability self-check diagnostic.
//!
//! Mirrors Go `daemon/core/system.go:CheckSysRequirements()`:
//! reads the kernel config file (trying `/boot/config-{kver}`, `/proc/config.gz`,
//! `/usr/lib/modules/{kver}/config` in order), checks each required feature group
//! via the same regexp patterns as the Go daemon, and checks whether tracefs is
//! mounted.  Results are emitted via `tracing` structured events rather than raw
//! stdout, so they appear in daemon logs at the appropriate severity level.
//!
//! Intended to run once at daemon startup (before the service pipeline starts).
//! It is entirely non-blocking and non-fatal: if the config file is not found
//! the diagnostic degrades gracefully (all checks skipped, warning logged).
use std::io::Read;

use regex::bytes::Regex;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Check definitions (verbatim from Go daemon reqsList JSON)
// ---------------------------------------------------------------------------

struct CheckSpec {
    item: &'static str,
    patterns: &'static [&'static str],
    reason: &'static str,
}

const CHECKS: &[CheckSpec] = &[
    CheckSpec {
        item: "kprobes",
        patterns: &[
            "CONFIG_KPROBES=y",
            "CONFIG_KPROBES_ON_FTRACE=y",
            "CONFIG_HAVE_KPROBES=y",
            "CONFIG_HAVE_KPROBES_ON_FTRACE=y",
            "CONFIG_KPROBE_EVENTS=y",
        ],
        reason: "KPROBES not fully supported by this kernel",
    },
    CheckSpec {
        item: "uprobes",
        patterns: &[
            "CONFIG_UPROBES=y",
            "CONFIG_UPROBE_EVENTS=y",
        ],
        reason: "UPROBES not supported — common error: cannot open uprobe_events",
    },
    CheckSpec {
        item: "ftrace",
        patterns: &["CONFIG_FTRACE=y"],
        reason: "CONFIG_FTRACE=y not set — common error: Error while loading kprobes: invalid argument",
    },
    CheckSpec {
        item: "syscalls",
        patterns: &[
            "CONFIG_HAVE_SYSCALL_TRACEPOINTS=y",
            "CONFIG_FTRACE_SYSCALLS=y",
            r"CONFIG_TRACING=[my]",
            r"CONFIG_EVENT_TRACING=[my]",
        ],
        reason: "CONFIG_FTRACE_SYSCALLS / CONFIG_HAVE_SYSCALL_TRACEPOINTS / CONFIG_TRACING / \
                 CONFIG_EVENT_TRACING not set — common error: error enabling tracepoint \
                 tracepoint/syscalls/sys_enter_execve: cannot read tracepoint id",
    },
    CheckSpec {
        item: "nfqueue",
        patterns: &[
            r"CONFIG_NETFILTER_NETLINK_QUEUE=[my]",
            r"CONFIG_NFT_QUEUE=[my]",
            r"CONFIG_NETFILTER_XT_TARGET_NFQUEUE=[my]",
        ],
        reason: "NFQUEUE netfilter extensions not supported \
                 (CONFIG_NETFILTER_NETLINK_QUEUE, CONFIG_NFT_QUEUE, \
                 CONFIG_NETFILTER_XT_TARGET_NFQUEUE)",
    },
    CheckSpec {
        item: "netlink",
        patterns: &[
            r"CONFIG_NETFILTER_NETLINK=[my]",
            r"CONFIG_NETFILTER_NETLINK_QUEUE=[my]",
            r"CONFIG_NETFILTER_NETLINK_ACCT=[my]",
            r"CONFIG_PROC_EVENTS=[my]",
        ],
        reason: "NETLINK extensions not supported \
                 (CONFIG_NETFILTER_NETLINK, CONFIG_NETFILTER_NETLINK_QUEUE, \
                 CONFIG_NETFILTER_NETLINK_ACCT, CONFIG_PROC_EVENTS)",
    },
    CheckSpec {
        item: "net diagnostics",
        patterns: &[
            r"CONFIG_INET_DIAG=[my]",
            r"CONFIG_INET_TCP_DIAG=[my]",
            r"CONFIG_INET_UDP_DIAG=[my]",
            r"CONFIG_INET_DIAG_DESTROY=[my]",
        ],
        reason: "One or more socket monitoring interfaces not enabled \
                 (CONFIG_INET_DIAG, CONFIG_INET_TCP_DIAG, CONFIG_INET_UDP_DIAG, \
                 CONFIG_INET_DIAG_DESTROY)",
    },
];

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result for a single feature group check.
pub struct CapCheckResult {
    pub item: &'static str,
    pub pass: bool,
    /// Patterns that were not found in the kernel config.
    pub missing_patterns: Vec<&'static str>,
    pub reason: &'static str,
}

/// Full diagnostic output from [`run`].
pub struct KernelDiagnostic {
    pub kernel_version: String,
    /// Path of the kernel config file that was successfully read, if any.
    pub config_source: Option<String>,
    pub checks: Vec<CapCheckResult>,
    pub tracefs_mounted: bool,
    /// `true` only when every check passed and tracefs is mounted.
    pub all_pass: bool,
}

impl KernelDiagnostic {
    /// Write a human-readable report to `stdout`.
    ///
    /// Intended for `--check-caps` CLI mode where the caller reads stdout.
    /// Uses plain `println!`/`eprintln!` rather than `tracing` so it works
    /// before the logging subsystem is initialised.
    pub fn print_report(&self) {
        println!(
            "\nChecking kernel capabilities for version {}",
            self.kernel_version
        );
        println!("{}", "-".repeat(78));

        if self.config_source.is_none() {
            eprintln!(
                "  ✘  kernel config not found in /boot/config-{ver}, \
                 /proc/config.gz, or /usr/lib/modules/{ver}/config",
                ver = self.kernel_version
            );
            eprintln!(
                "     See https://github.com/evilsocket/opensnitch/issues/774"
            );
        }

        for result in &self.checks {
            if result.pass {
                println!("  ✔  {}", result.item);
            } else {
                println!("  ✘  {}  —  {}", result.item, result.reason);
                for pat in &result.missing_patterns {
                    println!("       missing: {pat}");
                }
            }
        }

        if self.tracefs_mounted {
            println!("  ✔  tracefs mount");
        } else {
            println!(
                "  ✘  tracefs mount not found \
                 (mount -t tracefs none /sys/kernel/tracing/)"
            );
        }

        println!();
        if self.all_pass {
            println!("All kernel capability checks passed.");
        } else {
            eprintln!(
                "WARNING: some required kernel features are missing.\n\
                 See https://github.com/evilsocket/opensnitch/issues/774"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run the full kernel capability diagnostic and return a structured report.
///
/// Never panics; all I/O errors degrade gracefully.
pub fn run() -> KernelDiagnostic {
    let kernel_version = read_kernel_version();
    let (config_bytes, config_source) = read_kernel_config(&kernel_version);
    let tracefs_mounted = is_tracefs_mounted();

    let mut all_pass = tracefs_mounted;
    let checks = if let Some(ref content) = config_bytes {
        CHECKS
            .iter()
            .map(|spec| {
                let result = check_spec(spec, content);
                if !result.pass {
                    all_pass = false;
                }
                result
            })
            .collect()
    } else {
        all_pass = false;
        Vec::new()
    };

    KernelDiagnostic {
        kernel_version,
        config_source,
        checks,
        tracefs_mounted,
        all_pass,
    }
}

/// Emit the diagnostic results via structured `tracing` events.
pub fn log(diag: &KernelDiagnostic) {
    info!(
        kernel_version = %diag.kernel_version,
        config_source = diag.config_source.as_deref().unwrap_or("not found"),
        tracefs_mounted = diag.tracefs_mounted,
        "kernel capability diagnostic"
    );

    if diag.config_source.is_none() {
        warn!(
            kernel_version = %diag.kernel_version,
            "kernel config not found in /boot/config-{{kver}}, /proc/config.gz, \
             or /usr/lib/modules/{{kver}}/config — skipping feature checks; \
             see https://github.com/evilsocket/opensnitch/issues/774"
        );
        return;
    }

    for result in &diag.checks {
        if result.pass {
            info!(item = result.item, "✔");
        } else {
            warn!(
                item = result.item,
                missing = ?result.missing_patterns,
                reason = result.reason,
                "✘"
            );
        }
    }

    if diag.tracefs_mounted {
        info!(item = "tracefs mount", "✔");
    } else {
        warn!(
            item = "tracefs mount",
            hint = "mount -t tracefs none /sys/kernel/tracing/",
            "✘"
        );
    }

    if !diag.all_pass {
        warn!(
            "your kernel doesn't support some features OpenSnitch needs; \
             see https://github.com/evilsocket/opensnitch/issues/774"
        );
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_kernel_config(kver: &str) -> (Option<Vec<u8>>, Option<String>) {
    let paths = [
        format!("/boot/config-{kver}"),
        "/proc/config.gz".to_string(),
        format!("/usr/lib/modules/{kver}/config"),
    ];

    for path in &paths {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        if path.ends_with(".gz") {
            match read_gzip_file(path) {
                Ok(bytes) => return (Some(bytes), Some(path.clone())),
                Err(err) => {
                    tracing::debug!(path, "failed to read gzip kernel config: {err}");
                    continue;
                }
            }
        }
        match std::fs::read(path) {
            Ok(bytes) => return (Some(bytes), Some(path.clone())),
            Err(err) => {
                tracing::debug!(path, "failed to read kernel config: {err}");
                continue;
            }
        }
    }
    (None, None)
}

fn read_gzip_file(path: &str) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
}

fn is_tracefs_mounted() -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| s.contains("tracefs"))
        .unwrap_or(false)
}

fn check_spec(spec: &CheckSpec, config: &[u8]) -> CapCheckResult {
    let mut missing = Vec::new();
    for &pattern in spec.patterns {
        match Regex::new(pattern) {
            Ok(re) => {
                if re.find(config).is_none() {
                    missing.push(pattern);
                }
            }
            Err(err) => {
                tracing::debug!(pattern, "invalid kernel config pattern: {err}");
            }
        }
    }
    let pass = missing.is_empty();
    CapCheckResult {
        item: spec.item,
        pass,
        missing_patterns: missing,
        reason: spec.reason,
    }
}

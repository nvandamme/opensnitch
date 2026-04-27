//! Pure `/proc` filesystem readers.
//!
//! Mirrors Go `procmon/details.go` + `procmon/find.go`.
//! Each function is a standalone reader that accesses `/proc/<pid>/*` directly.
//! No caching, no service dependencies — callers own the caching layer.

use std::{collections::HashMap, fs, os::unix::fs::MetadataExt, path::PathBuf};

// ─── Constants ────────────────────────────────────────────────────────────────

pub(crate) const KERNEL_CONNECTION: &str = "Kernel connection";
const PROC_SELF_EXE: &str = "/proc/self/exe";
const DELETED_SUFFIX: &str = " (deleted)";

// ─── Structs (Go parity: procStatm, procIOstats) ─────────────────────────────

/// Memory page statistics from `/proc/<pid>/statm`.
/// Matches Go `procStatm` in `process.go`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcStatm {
    pub size: i64,
    pub resident: i64,
    #[allow(dead_code)]
    pub shared: i64,
    #[allow(dead_code)]
    pub text: i64,
    #[allow(dead_code)]
    pub lib: i64,
    #[allow(dead_code)]
    pub data: i64,
    #[allow(dead_code)]
    pub dt: i64,
}

/// I/O counters from `/proc/<pid>/io`.
/// Matches Go `procIOstats` in `process.go`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcIoStats {
    pub rchar: i64,
    pub wchar: i64,
    pub syscall_read: i64,
    pub syscall_write: i64,
    pub read_bytes: i64,
    pub write_bytes: i64,
}

/// A file-descriptor entry from `/proc/<pid>/fd/`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ProcDescriptor {
    pub name: String,
    pub sym_link: String,
}

// ─── Path helpers ─────────────────────────────────────────────────────────────

fn proc_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}"))
}

// ─── Individual readers (Go: details.go) ──────────────────────────────────────

/// Read the symlink `/proc/<pid>/exe`.
/// Go: `ReadExeLink()`.
pub(crate) fn read_exe_link(pid: u32) -> Option<String> {
    fs::read_link(proc_path(pid).join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Read `/proc/<pid>/comm` (short process name, max 16 chars).
/// Go: `ReadComm()`.
pub(crate) fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(proc_path(pid).join("comm"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Read the symlink `/proc/<pid>/cwd`.
/// Go: `ReadCwd()`.
pub(crate) fn read_cwd(pid: u32) -> Option<String> {
    fs::read_link(proc_path(pid).join("cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Read the symlink `/proc/<pid>/root`.
/// Go: `ReadRoot()`.
/// Returns `"/"` when the symlink is unreadable (matches Go fallback).
pub(crate) fn read_root(pid: u32) -> String {
    fs::read_link(proc_path(pid).join("root"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".to_owned())
}

/// Parse `/proc/<pid>/cmdline` into argument list.
/// Go: `ReadCmdline()`.
pub(crate) fn read_cmdline(pid: u32) -> Vec<String> {
    let data = match fs::read(proc_path(pid).join("cmdline")) {
        Ok(d) if !d.is_empty() => d,
        _ => return Vec::new(),
    };
    data.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Parse `/proc/<pid>/environ` into key→value map.
/// Go: `ReadEnv()`.
pub(crate) fn read_environ(pid: u32) -> HashMap<String, String> {
    let raw = match fs::read(proc_path(pid).join("environ")) {
        Ok(d) => d,
        Err(_) => return HashMap::new(),
    };
    let mut env = HashMap::new();
    for entry in raw.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&entry[..eq]).into_owned();
            let val = String::from_utf8_lossy(&entry[eq + 1..]).into_owned();
            env.insert(key, val);
        }
    }
    env
}

/// Read PPID from `/proc/<pid>/stat`.
/// Go: `ReadPPID()` — parses field after the closing `)` in stat.
pub(crate) fn read_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(proc_path(pid).join("stat")).ok()?;
    // Format: `pid (comm) state ppid ...`
    // comm can contain spaces and parens, so split after last `)`.
    let after_comm = stat.rsplit_once(") ")?.1;
    // Fields after comm: state(0) ppid(1) ...
    after_comm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
}

/// Read starttime (field 22, 0-indexed from stat start) from `/proc/<pid>/stat`.
/// After the comm closing `)`, starttime is at offset 19 (field index 21 minus
/// the pid and comm fields = 19 whitespace-separated tokens).
pub(crate) fn read_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(proc_path(pid).join("stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm
        .split_whitespace()
        .nth(19)
        .and_then(|s| s.parse().ok())
}

/// Read the UID of the process from `/proc/<pid>/status`.
pub(crate) fn read_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(proc_path(pid).join("status")).ok()?;
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
}

/// Read `/proc/<pid>/maps` raw content.
/// Go: `ReadMaps()`.
pub(crate) fn read_maps(pid: u32) -> Option<String> {
    fs::read_to_string(proc_path(pid).join("maps")).ok()
}

/// Parse `/proc/<pid>/statm` into memory page statistics.
/// Go: `ReadStatm()`.
/// Values are returned in **bytes** (page count × page size), matching Go.
pub(crate) fn read_statm(pid: u32) -> Option<ProcStatm> {
    let data = fs::read_to_string(proc_path(pid).join("statm")).ok()?;
    let page_size = page_size_bytes();
    let mut fields = data.split_whitespace();
    Some(ProcStatm {
        size: parse_field_pages(&mut fields, page_size),
        resident: parse_field_pages(&mut fields, page_size),
        shared: parse_field_pages(&mut fields, page_size),
        text: parse_field_pages(&mut fields, page_size),
        lib: parse_field_pages(&mut fields, page_size),
        data: parse_field_pages(&mut fields, page_size),
        dt: parse_field_pages(&mut fields, page_size),
    })
}

/// Parse `/proc/<pid>/io` into I/O counters.
/// Go: `readIOStats()`.
pub(crate) fn read_io_stats(pid: u32) -> Option<ProcIoStats> {
    let data = fs::read_to_string(proc_path(pid).join("io")).ok()?;
    let mut stats = ProcIoStats::default();
    for line in data.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next()?;
        let val: i64 = parts.next()?.trim().parse().ok()?;
        match key {
            "rchar" => stats.rchar = val,
            "wchar" => stats.wchar = val,
            "syscr" => stats.syscall_read = val,
            "syscw" => stats.syscall_write = val,
            "read_bytes" => stats.read_bytes = val,
            "write_bytes" => stats.write_bytes = val,
            _ => {}
        }
    }
    Some(stats)
}

/// Check if `/proc/<pid>` exists (process is alive).
/// Go: `IsAlive()`.
pub(crate) fn is_alive(pid: u32) -> bool {
    proc_path(pid).exists()
}

// ─── Path resolution (Go: ReadPath + SetPath + CleanPath) ─────────────────────

/// Resolve the executable path for a process, applying Go-compatible fixups:
/// - Strip ` (deleted)` suffix
/// - Resolve `/proc/self/exe` and `/proc/<pid>/fd/<n>` to real path
/// - Detect kernel connections (empty maps + unreadable exe)
///
/// Go: `ReadPath()` + `SetPath()` + `CleanPath()`.
pub(crate) fn resolve_exe_path(pid: u32) -> Option<String> {
    let base = proc_path(pid);
    let link = fs::read_link(base.join("exe")).ok();

    let raw_path = match link {
        Some(p) => {
            let s = p.to_string_lossy().into_owned();
            clean_path(pid, &s)
        }
        None => {
            // Unreadable exe — check if kernel connection.
            if let Ok(maps) = fs::read(&base.join("maps")) {
                if maps.is_empty() {
                    return Some(KERNEL_CONNECTION.to_owned());
                }
            }
            // Fall back to comm.
            return read_comm(pid);
        }
    };

    Some(raw_path)
}

/// Apply Go `CleanPath()` fixups on a raw exe link value.
fn clean_path(pid: u32, raw: &str) -> String {
    let mut path = raw.to_owned();

    // Strip " (deleted)" suffix (binary updated/removed while running).
    if path.ends_with(DELETED_SUFFIX) {
        path.truncate(path.len() - DELETED_SUFFIX.len());
    }

    // If the path points to /proc/... (e.g. /proc/self/exe, /proc/<pid>/fd/<n>),
    // resolve via the exe symlink or fall back to comm.
    if path.starts_with("/proc") {
        if path == PROC_SELF_EXE || path.starts_with(&format!("/proc/{pid}/fd/")) {
            if let Some(resolved) = read_exe_link(pid) {
                if !resolved.starts_with("/proc") {
                    return resolved;
                }
            }
        }
        if let Some(comm) = read_comm(pid) {
            return comm;
        }
    }

    path
}

// ─── PID enumeration + inode lookup (Go: find.go) ─────────────────────────────

/// Enumerate running PIDs from `/proc`.
/// Go: `getProcPids("/proc/")`.
pub(crate) fn list_pids() -> Vec<u32> {
    list_pids_in("/proc")
}

/// Enumerate PIDs (or TIDs) in a given `/proc`-like directory.
fn list_pids_in(dir: &str) -> Vec<u32> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut pids: Vec<u32> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    // Sort by inode mtime descending (most recent first), matching Go's sortPidsByTime.
    // We use the directory's metadata mtime as a proxy.
    pids.sort_unstable_by(|a, b| {
        let ma = fs::metadata(format!("/proc/{a}"))
            .map(|m| m.mtime())
            .unwrap_or(0);
        let mb = fs::metadata(format!("/proc/{b}"))
            .map(|m| m.mtime())
            .unwrap_or(0);
        mb.cmp(&ma)
    });
    pids
}

/// List file-descriptor entries in `/proc/<pid>/fd/`.
/// Go: `lookupPidDescriptors()`.
pub(crate) fn list_descriptors(pid: u32) -> Vec<ProcDescriptor> {
    let fd_dir = proc_path(pid).join("fd");
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let sym_link = fs::read_link(e.path())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            Some(ProcDescriptor { name, sym_link })
        })
        .collect()
}

/// Find the PID that owns a socket inode by scanning `/proc/*/fd/`.
/// Go: `lookupPidInProc("/proc/", expect, inodeKey, inode)`.
///
/// `inode` is the socket inode number; this function looks for
/// `socket:[<inode>]` symlinks across all running processes.
pub(crate) fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let expect = format!("socket:[{inode}]");
    for pid in list_pids() {
        let fd_dir = proc_path(pid).join("fd");
        let entries = match fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            if let Ok(link) = fs::read_link(entry.path()) {
                if link.to_string_lossy() == expect {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Check if a specific PID owns a socket inode.
/// Go: `inodeFound()`.
pub(crate) fn pid_owns_inode(pid: u32, inode: u64) -> bool {
    let expect = format!("socket:[{inode}]");
    let fd_dir = proc_path(pid).join("fd");
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        if let Ok(link) = fs::read_link(entry.path()) {
            if link.to_string_lossy() == expect {
                return true;
            }
        }
    }
    false
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn page_size_bytes() -> i64 {
    // SAFETY: sysconf(_SC_PAGESIZE) is always safe.
    unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) }
}

fn parse_field_pages<'a>(iter: &mut impl Iterator<Item = &'a str>, page_size: i64) -> i64 {
    iter.next().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) * page_size
}

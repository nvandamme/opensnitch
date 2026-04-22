use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
};

use anyhow::{Context, Result};
use md5::{Digest as Md5Digest, Md5};
use nix::libc;
use sha1::Sha1;
use sha2::Sha256;

use crate::models::process_state::{ProcessInfo, ProcessNode};

use super::ProcessService;

impl ProcessService {
    /// Full process inspection including exe hash computation.
    ///
    /// Prefer [`inspect_process_no_hash`] + background [`compute_process_hashes`] on
    /// the connection hot path to avoid blocking the thread pool on large binaries.
    #[allow(dead_code)]
    pub(super) fn inspect_process(pid: u32) -> Result<ProcessInfo> {
        let mut info = Self::inspect_process_no_hash(pid)?;
        if let Some((md5, sha1, sha256)) = Self::compute_process_hashes(pid) {
            info.process_hash_md5 = Some(md5);
            info.process_hash_sha1 = Some(sha1);
            info.process_hash = Some(sha256);
        }
        Ok(info)
    }

    /// Process inspection without exe hash computation.
    ///
    /// Returns immediately with `process_hash*` fields set to `None`.  Call
    /// [`compute_process_hashes`] asynchronously and update the process cache when
    /// complete to enable hash-based rule matching on subsequent connections.
    pub(super) fn inspect_process_no_hash(pid: u32) -> Result<ProcessInfo> {
        let path = fs::read_link(format!("/proc/{pid}/exe"))
            .with_context(|| format!("read exe for pid {pid}"))?
            .to_string_lossy()
            .into_owned();

        let args: Vec<String> = fs::read(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let raw_environ = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        let env_entries_hint = if raw_environ.is_empty() {
            0
        } else {
            raw_environ.iter().filter(|&&byte| byte == 0).count() + 1
        };
        let mut env_preview = Vec::with_capacity(env_entries_hint);
        let mut env_map = HashMap::with_capacity(env_entries_hint);
        for entry in raw_environ.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            let entry_text = String::from_utf8_lossy(entry).into_owned();
            if let Some((key, value)) = entry_text.split_once('=') {
                env_map.insert(key.to_string(), value.to_string());
            }
            env_preview.push(entry_text);
        }

        let parent_chain = Self::build_parent_chain(pid);

        Ok(ProcessInfo {
            pid,
            path,
            args,
            cwd,
            env_preview,
            env_map,
            process_hash: None,
            process_hash_md5: None,
            process_hash_sha1: None,
            parent_chain,
        })
    }

    pub(super) fn compute_process_hashes(pid: u32) -> Option<(String, String, String)> {
        let exe_path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;

        // Fast path: if IMA has already measured this file, read the SHA-256 digest
        // directly from the `security.ima` xattr — avoids reading the whole binary.
        if let Some(sha256) = Self::read_ima_sha256_xattr(&exe_path) {
            // IMA only provides SHA-256; compute md5/sha1 from file for full compat.
            let (md5, sha1) = Self::compute_md5_sha1(&exe_path)?;
            return Some((md5, sha1, sha256));
        }

        Self::compute_hashes_from_file(&exe_path)
    }

    /// Read the SHA-256 digest from the IMA `security.ima` xattr if present.
    ///
    /// IMA stores the xattr as: `[header: 4 bytes] [digest: 32 bytes]` for the most
    /// common `IMA_DIGSIG_APPRAISE_TYPE_IMA` (type 0x03) format with SHA-256 (algorithm 4).
    /// Returns `None` if xattr is absent, the format is unrecognised, or reads fail.
    fn read_ima_sha256_xattr(path: &std::path::Path) -> Option<String> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path_c = CString::new(path.as_os_str().as_bytes()).ok()?;
        let attr_name = b"security.ima\0";

        // Query size first.
        let size = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                attr_name.as_ptr() as *const libc::c_char,
                std::ptr::null_mut(),
                0,
            )
        };
        if size <= 0 {
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let read = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                attr_name.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if read <= 0 || read as usize != buf.len() {
            return None;
        }

        // IMA xattr layout (common formats):
        //   [0]: type field.  0x03 = IMA_DIGSIG_APPRAISE_TYPE_IMA (hash).
        //   [1]: hash algorithm (see include/uapi/linux/hash_info.h):
        //        0=md5, 1=sha1, 2=rmd160, 4=sha256 (HASH_ALGO_SHA256)
        //   [2..3]: unused/reserved
        //   [4..]: digest bytes
        if buf.len() < 36 {
            return None; // need at least 4-byte header + 32-byte SHA-256
        }
        let header_type = buf[0];
        let algo = buf[1];

        const IMA_HASH_TYPE: u8 = 0x03;
        const HASH_ALGO_SHA256: u8 = 4;

        if header_type == IMA_HASH_TYPE && algo == HASH_ALGO_SHA256 {
            let digest = &buf[4..36];
            return Some(digest.iter().map(|b| format!("{b:02x}")).collect());
        }

        None
    }

    fn compute_md5_sha1(path: &std::path::Path) -> Option<(String, String)> {
        let mut file = fs::File::open(path).ok()?;
        let mut hasher_md5 = Md5::new();
        let mut hasher_sha1 = Sha1::new();
        let mut buf = [0_u8; 8192];
        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher_md5.update(&buf[..n]);
            hasher_sha1.update(&buf[..n]);
        }
        Some((
            format!("{:x}", hasher_md5.finalize()),
            format!("{:x}", hasher_sha1.finalize()),
        ))
    }

    fn compute_hashes_from_file(path: &std::path::Path) -> Option<(String, String, String)> {
        let mut file = fs::File::open(path).ok()?;
        let mut hasher_md5 = Md5::new();
        let mut hasher_sha1 = Sha1::new();
        let mut hasher = Sha256::new();
        let mut buf = [0_u8; 8192];

        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher_md5.update(&buf[..n]);
            hasher_sha1.update(&buf[..n]);
            hasher.update(&buf[..n]);
        }

        let digest_md5 = hasher_md5.finalize();
        let digest_sha1 = hasher_sha1.finalize();
        let digest = hasher.finalize();
        Some((
            format!("{:x}", digest_md5),
            format!("{:x}", digest_sha1),
            format!("{:x}", digest),
        ))
    }

    fn build_parent_chain(pid: u32) -> Vec<ProcessNode> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = pid;

        loop {
            if !seen.insert(current) {
                break;
            }

            let exe = fs::read_link(format!("/proc/{current}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| format!("[{current}]"));

            chain.push(ProcessNode {
                pid: current,
                path: exe,
            });

            if current <= 1 || chain.len() >= 64 {
                break;
            }

            let status = match fs::read_to_string(format!("/proc/{current}/status")) {
                Ok(s) => s,
                Err(_) => break,
            };

            let ppid = status
                .lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u32>().ok());

            match ppid {
                Some(0) | None => break,
                Some(p) => current = p,
            }
        }

        chain
    }

    pub(super) fn read_proc_starttime(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rsplit_once(") ")?.1;
        after_comm
            .split_whitespace()
            .nth(19)
            .and_then(|value| value.parse::<u64>().ok())
    }
}

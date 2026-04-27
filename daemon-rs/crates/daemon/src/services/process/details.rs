use std::{collections::HashSet, fs, io::Read};

use anyhow::{Result, anyhow};
use md5::{Digest as Md5Digest, Md5};
use nix::libc;
use sha1::Sha1;
use sha2::Sha256;

use crate::models::process::state::{ProcessExtraInfo, ProcessInfo, ProcessNode};
use crate::platform::procmon::procfs;

use super::ProcessService;

impl ProcessService {
    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    /// Process inspection without exe hash computation.
    ///
    /// Returns immediately with `process_hash*` fields set to `None`.  Call
    /// [`compute_process_hashes`] asynchronously and update the process cache when
    /// complete to enable hash-based rule matching on subsequent connections.
    pub(super) fn inspect_process_no_hash(pid: u32) -> Result<ProcessInfo> {
        let path = procfs::resolve_exe_path(pid)
            .ok_or_else(|| anyhow!("cannot resolve exe for pid {pid}"))?;

        let comm = procfs::read_comm(pid);
        let root = procfs::read_root(pid);
        let uid = procfs::read_uid(pid);
        let args = procfs::read_cmdline(pid);
        let cwd = procfs::read_cwd(pid);
        let env_map = procfs::read_environ(pid);

        let env_preview: Vec<String> = env_map.iter().map(|(k, v)| format!("{k}={v}")).collect();

        let parent_chain = Self::build_parent_chain(pid);

        Ok(ProcessInfo {
            pid,
            path,
            comm,
            root,
            uid,
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
        let exe_path = procfs::read_exe_link(pid).map(std::path::PathBuf::from)?;

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
            return Some(Self::hex_lower(digest));
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
            Self::hex_lower(&hasher_md5.finalize()),
            Self::hex_lower(&hasher_sha1.finalize()),
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
            Self::hex_lower(&digest_md5),
            Self::hex_lower(&digest_sha1),
            Self::hex_lower(&digest),
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

            let exe = procfs::read_exe_link(current).unwrap_or_else(|| format!("[{current}]"));

            chain.push(ProcessNode {
                pid: current,
                path: exe,
            });

            if current <= 1 || chain.len() >= 64 {
                break;
            }

            match procfs::read_ppid(current) {
                Some(0) | None => break,
                Some(p) => current = p,
            }
        }

        chain
    }

    pub(super) fn read_proc_starttime(pid: u32) -> Option<u64> {
        procfs::read_starttime(pid)
    }

    /// Collect extra runtime information for a running process.
    /// Collect volatile extra information for a running process.
    /// Go: `Process.GetExtraInfo()` → `ReadEnv`, `readDescriptors`, `readIOStats`, `readStatus`.
    pub(crate) fn get_extra_info(pid: u32) -> ProcessExtraInfo {
        let env = procfs::read_environ(pid);
        let descriptors = procfs::read_descriptors(pid);
        let io_stats = procfs::read_io_stats(pid);
        // Go readStatus() reads status, stat, stack, then maps and statm.
        let status = procfs::read_status(pid);
        let stat = procfs::read_stat(pid);
        let stack = procfs::read_stack(pid);
        let maps = procfs::read_maps(pid).unwrap_or_default();
        let statm = procfs::read_statm(pid);

        ProcessExtraInfo {
            env,
            descriptors,
            io_stats,
            statm,
            status,
            stat,
            stack,
            maps,
        }
    }
}

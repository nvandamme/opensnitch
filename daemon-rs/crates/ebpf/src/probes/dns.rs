#![allow(non_snake_case)]

use core::ptr;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_user_buf,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use opensnitch_ebpf_common::{
    dns::{
        AF_INET, AF_INET6, AF_UNRESOLVED, ADDRINFO_ARGS_MAX_ENTRIES, DnsEvent,
        GETHOSTBYNAME_ARGS_MAX_ENTRIES, HOST_LEN, MAX_IPS, NODE_LEN,
    },
    maps::EVENTS_MAP_MAX_ENTRIES,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Hostent {
    h_name: *const u8,
    h_aliases: *const *const u8,
    h_addrtype: i32,
    h_length: i32,
    h_addr_list: *const *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddrInfo {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: usize,
    ai_addr: *const u8,
    ai_canonname: *const u8,
    ai_next: *const AddrInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    _sin_family: u16,
    _sin_port: u16,
    sin_addr: [u8; 4],
    _sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    _sin6_family: u16,
    _sin6_port: u16,
    _sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    _sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddrInfoArgsCache {
    // Store the pointer as raw bytes so AddrInfoArgsCache has alignment 1.
    // Any field with alignment > 1 (e.g. usize / u64) would cause Rust to
    // insert an alignment-check panic path that calls into .text.unlikely.,
    // which Aya cannot resolve during BPF program loading.
    addrinfo_ptr: [u8; 8],
    node: [u8; NODE_LEN],
}

impl AddrInfoArgsCache {
    #[inline(always)]
    fn get_addrinfo_ptr(&self) -> *const *const AddrInfo {
        let v = (self.addrinfo_ptr[0] as u64)
            | ((self.addrinfo_ptr[1] as u64) << 8)
            | ((self.addrinfo_ptr[2] as u64) << 16)
            | ((self.addrinfo_ptr[3] as u64) << 24)
            | ((self.addrinfo_ptr[4] as u64) << 32)
            | ((self.addrinfo_ptr[5] as u64) << 40)
            | ((self.addrinfo_ptr[6] as u64) << 48)
            | ((self.addrinfo_ptr[7] as u64) << 56);
        v as *const *const AddrInfo
    }
}

/// Caches the queried hostname for `gethostbyname` / `gethostbyname2` so that
/// the corresponding uretprobe can emit a meaningful failure event when the
/// call returns NULL.
#[repr(C)]
#[derive(Clone, Copy)]
struct GethostbynameArgsCache {
    name: [u8; NODE_LEN],
}

impl GethostbynameArgsCache {
}

#[map]
static ADDRINFO_ARGS_HASH: HashMap<u32, AddrInfoArgsCache> =
    HashMap::with_max_entries(ADDRINFO_ARGS_MAX_ENTRIES, 0);

#[map]
static ADDRINFO_ARGS_SCRATCH: PerCpuArray<AddrInfoArgsCache> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static GETHOSTBYNAME_ARGS_HASH: HashMap<u32, GethostbynameArgsCache> =
    HashMap::with_max_entries(GETHOSTBYNAME_ARGS_MAX_ENTRIES, 0);

#[map]
static GETHOSTBYNAME_ARGS_SCRATCH: PerCpuArray<GethostbynameArgsCache> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static DNS_EVENT_SCRATCH: PerCpuArray<DnsEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "events")]
pub(crate) static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_MAP_MAX_ENTRIES, 0);

#[inline(always)]
fn current_tid() -> u32 {
    bpf_get_current_pid_tgid() as u32
}

#[inline(always)]
fn read_user_buf<const N: usize>(src: *const u8, dst: &mut [u8; N]) -> bool {
    if src.is_null() {
        return false;
    }

    unsafe { bpf_probe_read_user_buf(src, &mut dst[..]).is_ok() }
}

#[inline(always)]
fn read_user_value<T: Copy>(src: *const T) -> Option<T> {
    if src.is_null() {
        return None;
    }

    let mut out = core::mem::MaybeUninit::<T>::uninit();
    let ret = unsafe {
        aya_ebpf::helpers::r#gen::bpf_probe_read_user(
            out.as_mut_ptr().cast(),
            core::mem::size_of::<T>() as u32,
            src.cast(),
        )
    };

    if ret == 0 {
        Some(unsafe { out.assume_init() })
    } else {
        None
    }
}

#[inline(always)]
fn emit(data: *const DnsEvent) {
    let _ = unsafe { EVENTS.output(&*data, 0) };
}

#[inline(always)]
/// Emits a failure event carrying `error_code` (EAI_* for getaddrinfo, 0 for
/// gethostbyname where h_errno is not accessible from a uretprobe).
/// `addr_type` is set to `AF_UNRESOLVED` so the daemon parser can distinguish
/// these from normal answer events.
fn emit_resolution_failed(name: &[u8; NODE_LEN], error_code: i32) {
    let Some(data) = event_buf() else { return };
    unsafe {
        (*data).addr_type = AF_UNRESOLVED;
    }
    let code = error_code.to_ne_bytes();
    unsafe {
        (*data).ip[0] = code[0];
        (*data).ip[1] = code[1];
        (*data).ip[2] = code[2];
        (*data).ip[3] = code[3];
    }
    let host_ptr = (data as *mut u8).wrapping_add(core::mem::offset_of!(DnsEvent, host));
    copy_cached_node(name, host_ptr);
    emit(data);
}

#[inline(always)]
fn event_buf() -> Option<*mut DnsEvent> {
    DNS_EVENT_SCRATCH.get_ptr_mut(0)
}

#[inline(always)]
fn gethostbyname_cache_buf() -> Option<*mut GethostbynameArgsCache> {
    GETHOSTBYNAME_ARGS_SCRATCH.get_ptr_mut(0)
}

#[inline(always)]
fn addrinfo_cache_buf() -> Option<*mut AddrInfoArgsCache> {
    ADDRINFO_ARGS_SCRATCH.get_ptr_mut(0)
}

#[inline(always)]
fn copy_cached_node(node: &[u8; NODE_LEN], dst: *mut u8) {
    unsafe {
        ptr::write(dst, 0);
    }
    let mut i = 0;
    while i + 1 < HOST_LEN && i + 1 < NODE_LEN {
        unsafe {
            ptr::write(dst.add(i), node[i]);
        }
        if node[i] == 0 {
            break;
        }
        i += 1;
    }

    if i + 1 >= HOST_LEN {
        unsafe {
            ptr::write(dst.add(HOST_LEN - 1), 0);
        }
    }
}

// ---------------------------------------------------------------------------
// gethostbyname / gethostbyname2
// ---------------------------------------------------------------------------

/// Common entry handler for `gethostbyname` and `gethostbyname2`.
/// Caches the queried hostname keyed by thread-id so the return probe can
/// emit a failure event if the call returns NULL.
#[inline(always)]
fn handle_gethostbyname_entry(ctx: ProbeContext) -> u32 {
    let Some(name_ptr) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    if name_ptr.is_null() {
        return 0;
    }
    let Some(cached) = gethostbyname_cache_buf() else {
        return 0;
    };
    if !read_user_buf(name_ptr, unsafe { &mut (*cached).name }) {
        return 0;
    }
    let tid = current_tid();
    let _ = GETHOSTBYNAME_ARGS_HASH.insert(&tid, unsafe { &*cached }, 0);
    0
}

/// Common return handler for `gethostbyname` and `gethostbyname2`.
/// On NULL return, emits an `AF_UNRESOLVED` failure event using the cached
/// queried hostname, then clears the args-cache entry. Successful returns are
/// currently ignored in this path to keep verifier-friendly code generation.
#[inline(always)]
fn handle_gethostbyname_ret(ctx: RetProbeContext) -> u32 {
    let tid = current_tid();

    let ret_ptr = match ctx.ret::<*const Hostent>() {
        Some(ptr) => ptr,
        None => ptr::null(),
    };
    if ret_ptr.is_null() {
        if let Some(cached) = unsafe { GETHOSTBYNAME_ARGS_HASH.get(&tid) } {
            emit_resolution_failed(&cached.name, 0);
        }
    }

    let _ = GETHOSTBYNAME_ARGS_HASH.remove(&tid);
    0
}

#[uprobe]
pub fn uprobe__gethostbyname(ctx: ProbeContext) -> u32 {
    handle_gethostbyname_entry(ctx)
}

#[uretprobe]
pub fn uretprobe__gethostbyname(ctx: RetProbeContext) -> u32 {
    handle_gethostbyname_ret(ctx)
}

/// `gethostbyname2(name, af)` returns the same `struct hostent *` as
/// `gethostbyname`; probe it with the same entry/return logic.
#[uprobe]
pub fn uprobe__gethostbyname2(ctx: ProbeContext) -> u32 {
    handle_gethostbyname_entry(ctx)
}

#[uretprobe]
pub fn uretprobe__gethostbyname2(ctx: RetProbeContext) -> u32 {
    handle_gethostbyname_ret(ctx)
}

// ---------------------------------------------------------------------------
// getaddrinfo
// ---------------------------------------------------------------------------

#[uprobe]
pub fn uprobe__getaddrinfo(ctx: ProbeContext) -> u32 {
    let Some(node) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let Some(addrinfo_ptr) = ctx.arg::<*const *const AddrInfo>(3) else {
        return 0;
    };

    if node.is_null() || addrinfo_ptr.is_null() {
        return 0;
    }

    let Some(cached) = addrinfo_cache_buf() else {
        return 0;
    };

    let addr = addrinfo_ptr as usize as u64;
    unsafe {
        (*cached).addrinfo_ptr[0] = addr as u8;
        (*cached).addrinfo_ptr[1] = (addr >> 8) as u8;
        (*cached).addrinfo_ptr[2] = (addr >> 16) as u8;
        (*cached).addrinfo_ptr[3] = (addr >> 24) as u8;
        (*cached).addrinfo_ptr[4] = (addr >> 32) as u8;
        (*cached).addrinfo_ptr[5] = (addr >> 40) as u8;
        (*cached).addrinfo_ptr[6] = (addr >> 48) as u8;
        (*cached).addrinfo_ptr[7] = (addr >> 56) as u8;
    }

    if unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(node, &mut (*cached).node) }.is_err() {
        return 0;
    }

    let tid = current_tid();
    let _ = ADDRINFO_ARGS_HASH.insert(&tid, unsafe { &*cached }, 0);
    0
}

#[uretprobe]
pub fn uretprobe__getaddrinfo(ctx: RetProbeContext) -> u32 {
    let tid = current_tid();

    // Check getaddrinfo(3) return code: 0 = EAI_SUCCESS, non-zero = EAI_* error.
    // We capture it before the cache lookup so the error code is always paired
    // with the cached hostname that triggered the failed lookup.
    let ret_code = ctx.ret::<i32>().unwrap_or(-1);

    let cached = match unsafe { ADDRINFO_ARGS_HASH.get(&tid) } {
        Some(value) => value,
        None => return 0,
    };

    if ret_code != 0 {
        // Emit a failure event so the daemon can observe NXDOMAIN / EAI_AGAIN
        // / EAI_FAIL etc. with the original queried hostname.
        emit_resolution_failed(&cached.node, ret_code);
        let _ = ADDRINFO_ARGS_HASH.remove(&tid);
        return 0;
    }

    let addrinfo_ptr = cached.get_addrinfo_ptr();
    let mut res = match read_user_value(addrinfo_ptr) {
        Some(value) => value,
        None => {
            let _ = ADDRINFO_ARGS_HASH.remove(&tid);
            return 0;
        }
    };

    let mut i = 0;
    while i < MAX_IPS {
        if res.is_null() {
            break;
        }

        let Some(data) = event_buf() else {
            break;
        };

        let ai_family_ptr = unsafe { ptr::addr_of!((*res).ai_family) };
        let addr_type = match read_user_value(ai_family_ptr) {
            Some(family) => family as u32,
            None => break,
        };
        unsafe {
            (*data).addr_type = addr_type;
        }

        let ai_addr_ptr = unsafe { ptr::addr_of!((*res).ai_addr) };
        let ai_addr = match read_user_value(ai_addr_ptr) {
            Some(addr) => addr,
            None => break,
        };

        if ai_addr.is_null() {
            break;
        }

        let ip_ptr = (data as *mut u8).wrapping_add(core::mem::offset_of!(DnsEvent, ip));

        if addr_type == AF_INET {
            let ipv4 = ai_addr as *const SockAddrIn;
            let sin_addr_ptr = unsafe { ptr::addr_of!((*ipv4).sin_addr) };
            let ret = unsafe {
                aya_ebpf::helpers::r#gen::bpf_probe_read_user(
                    ip_ptr.cast(),
                    4,
                    sin_addr_ptr.cast(),
                )
            };
            if ret != 0 {
                break;
            }
        } else if addr_type == AF_INET6 {
            let ipv6 = ai_addr as *const SockAddrIn6;
            let sin6_addr_ptr = unsafe { ptr::addr_of!((*ipv6).sin6_addr) };
            let ret = unsafe {
                aya_ebpf::helpers::r#gen::bpf_probe_read_user(
                    ip_ptr.cast(),
                    16,
                    sin6_addr_ptr.cast(),
                )
            };
            if ret != 0 {
                break;
            }
        } else {
            break;
        }

        let host_ptr = (data as *mut u8).wrapping_add(core::mem::offset_of!(DnsEvent, host));
        copy_cached_node(&cached.node, host_ptr);
        emit(data);

        let next_ptr = unsafe { ptr::addr_of!((*res).ai_next) };
        res = match read_user_value(next_ptr) {
            Some(next) => next,
            None => break,
        };
        i += 1;
    }

    let _ = ADDRINFO_ARGS_HASH.remove(&tid);
    0
}


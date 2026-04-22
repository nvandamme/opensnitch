use std::{
    collections::{HashMap, HashSet},
    sync::{OnceLock, RwLock},
};

use crate::utils::path_text::lossy_os;

fn fallback_interface_name_cache() -> &'static RwLock<HashMap<u32, String>> {
    static CACHE: OnceLock<RwLock<HashMap<u32, String>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(interface_name_map()))
}

fn cached_interface_name_by_index(index: u32) -> Option<String> {
    if let Ok(cache) = fallback_interface_name_cache().read()
        && let Some(name) = cache.get(&index)
    {
        return Some(name.clone());
    }

    // Refresh once on miss to account for interface lifecycle changes.
    let refreshed = interface_name_map();
    let hit = refreshed.get(&index).cloned();
    if let Ok(mut cache) = fallback_interface_name_cache().write() {
        *cache = refreshed;
    }
    hit
}

pub(crate) fn interface_name_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return map;
    };

    for entry in entries.flatten() {
        let iface_name = lossy_os(entry.file_name());
        let ifindex_path = entry.path().join("ifindex");
        let Ok(value) = std::fs::read_to_string(ifindex_path) else {
            continue;
        };
        let Ok(ifindex) = value.trim().parse::<u32>() else {
            continue;
        };
        map.insert(ifindex, iface_name);
    }

    map
}

pub(crate) fn local_ip_addrs() -> HashSet<String> {
    // Intentionally uncached: local addresses can change quickly (VPN, DHCP, netns),
    // so callers should get a fresh snapshot on each call.
    let mut out = HashSet::new();
    let mut ifaddr_ptr: *mut nix::libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: libc allocates a linked list and writes its head to `ifaddr_ptr` on success.
    if unsafe { nix::libc::getifaddrs(&mut ifaddr_ptr) } != 0 || ifaddr_ptr.is_null() {
        return out;
    }

    // SAFETY: Walk the linked list returned by getifaddrs until null; all pointers are owned by libc
    // and released once with freeifaddrs below.
    unsafe {
        let mut cur = ifaddr_ptr;
        while !cur.is_null() {
            let ifa = &*cur;
            let sa = ifa.ifa_addr;
            if !sa.is_null() {
                let family = (*sa).sa_family as i32;
                if family == nix::libc::AF_INET {
                    let sin = &*(sa as *const nix::libc::sockaddr_in);
                    let addr = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    out.insert(addr.to_string());
                } else if family == nix::libc::AF_INET6 {
                    let sin6 = &*(sa as *const nix::libc::sockaddr_in6);
                    let addr = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    out.insert(addr.to_string());
                }
            }

            cur = ifa.ifa_next;
        }

        nix::libc::freeifaddrs(ifaddr_ptr);
    }

    out
}

pub(crate) fn interface_name_by_index(index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }

    let mut name = [0_i8; nix::libc::IF_NAMESIZE];
    // SAFETY: if_indextoname writes a NUL-terminated interface name into the provided fixed-size buffer.
    let ptr = unsafe { nix::libc::if_indextoname(index, name.as_mut_ptr()) };
    if !ptr.is_null() {
        // SAFETY: libc guarantees returned pointer references a NUL-terminated string in `name`.
        return Some(
            unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        );
    }

    cached_interface_name_by_index(index)
}

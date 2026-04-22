#![allow(non_snake_case)]

use core::{mem::size_of, ptr};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{kprobe, kretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use core::mem::MaybeUninit;

const MAPSIZE: u32 = 12_000;
const TASK_COMM_LEN: usize = 16;

const TCP_KEY_LEN: usize = 12;
const TCPV6_KEY_LEN: usize = 36;
const UDP_KEY_LEN: usize = 12;
const UDPV6_KEY_LEN: usize = 36;
const VALUE_LEN: usize = 32;

const SKC_DADDR_OFF: usize = 0x00;
const SKC_RCV_SADDR_OFF: usize = 0x04;
const SKC_DPORT_OFF: usize = 0x0c;
const SKC_NUM_OFF: usize = 0x0e;
const SKC_V6_DADDR_OFF: usize = 0x38;
const SKC_V6_RCV_SADDR_OFF: usize = 0x48;
const SOCKET_SK_OFF: usize = 0x18;
const SK_FAMILY_OFF: usize = 0x10;
const SK_PROTOCOL_OFF: usize = 0x224;

const MSG_NAME_OFF: usize = 0x00;
const MSG_CONTROL_OFF: usize = 0x38;

const SOCKADDR_IN_PORT_OFF: usize = 0x02;
const SOCKADDR_IN_ADDR_OFF: usize = 0x04;

const SOCKADDR_IN6_PORT_OFF: usize = 0x02;
const SOCKADDR_IN6_ADDR_OFF: usize = 0x08;

const IN_PKTINFO_SPEC_DST_OFF: usize = 0x14;
const IN6_PKTINFO_ADDR_OFF: usize = 0x10;

// Best-effort offsets for x86_64 `struct sk_buff` fields used by iptunnel_xmit.
const SKB_HEAD_OFF: usize = 0xc8;
const SKB_TRANSPORT_HEADER_OFF: usize = 0xc0;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_UDP: u8 = 17;

#[map]
#[allow(non_upper_case_globals)]
static tcpMap: HashMap<[u8; TCP_KEY_LEN], [u8; VALUE_LEN]> =
    HashMap::with_max_entries(MAPSIZE + 1, 0);

#[map]
#[allow(non_upper_case_globals)]
static tcpv6Map: HashMap<[u8; TCPV6_KEY_LEN], [u8; VALUE_LEN]> =
    HashMap::with_max_entries(MAPSIZE + 2, 0);

#[map]
#[allow(non_upper_case_globals)]
static udpMap: HashMap<[u8; UDP_KEY_LEN], [u8; VALUE_LEN]> =
    HashMap::with_max_entries(MAPSIZE + 3, 0);

#[map]
#[allow(non_upper_case_globals)]
static udpv6Map: HashMap<[u8; UDPV6_KEY_LEN], [u8; VALUE_LEN]> =
    HashMap::with_max_entries(MAPSIZE + 4, 0);

#[map]
#[allow(non_upper_case_globals)]
static tcpsock: HashMap<u64, u64> = HashMap::with_max_entries(300, 0);

#[map]
#[allow(non_upper_case_globals)]
static tcpv6sock: HashMap<u64, u64> = HashMap::with_max_entries(300, 0);

#[map]
#[allow(non_upper_case_globals)]
static icmpsock: HashMap<u64, u64> = HashMap::with_max_entries(300, 0);

#[inline(always)]
fn read_kernel<T: Copy>(src: *const T) -> Option<T> {
    if src.is_null() {
        return None;
    }

    let mut out = unsafe { core::mem::zeroed::<T>() };
    let ret = unsafe {
        aya_ebpf::helpers::r#gen::bpf_probe_read_kernel(
            (&mut out as *mut T).cast(),
            size_of::<T>() as u32,
            src.cast(),
        )
    };
    if ret == 0 { Some(out) } else { None }
}

#[inline(always)]
fn read_kernel_u16(base: *const u8, off: usize) -> Option<u16> {
    read_kernel(base.wrapping_add(off).cast())
}

#[inline(always)]
fn read_kernel_u32(base: *const u8, off: usize) -> Option<u32> {
    read_kernel(base.wrapping_add(off).cast())
}

#[inline(always)]
fn read_kernel_u64(base: *const u8, off: usize) -> Option<u64> {
    read_kernel(base.wrapping_add(off).cast())
}

#[inline(always)]
fn read_kernel_arr16(base: *const u8, off: usize) -> Option<[u8; 16]> {
    read_kernel(base.wrapping_add(off).cast())
}

#[inline(always)]
fn write_u16_ne(buf: *mut u8, off: usize, v: u16) {
    let b = v.to_ne_bytes();
    unsafe {
        ptr::write(buf.add(off), b[0]);
        ptr::write(buf.add(off + 1), b[1]);
    }
}

#[inline(always)]
fn write_u32_ne(buf: *mut u8, off: usize, v: u32) {
    let b = v.to_ne_bytes();
    unsafe {
        ptr::write(buf.add(off), b[0]);
        ptr::write(buf.add(off + 1), b[1]);
        ptr::write(buf.add(off + 2), b[2]);
        ptr::write(buf.add(off + 3), b[3]);
    }
}

#[inline(always)]
fn write_u64_ne(buf: *mut u8, off: usize, v: u64) {
    let b = v.to_ne_bytes();
    let mut i = 0;
    while i < 8 {
        unsafe {
            ptr::write(buf.add(off + i), b[i]);
        }
        i += 1;
    }
}

#[inline(always)]
fn write_arr16(buf: *mut u8, off: usize, v: &[u8; 16]) {
    let mut i = 0;
    while i < 16 {
        unsafe {
            ptr::write(buf.add(off + i), v[i]);
        }
        i += 1;
    }
}

#[inline(always)]
fn ntohs(v: u16) -> u16 {
    u16::from_be(v)
}

#[inline(always)]
fn current_pid() -> u64 {
    bpf_get_current_pid_tgid() >> 32
}

#[inline(always)]
fn current_uid_u64() -> u64 {
    (bpf_get_current_uid_gid() & 0xffff_ffff) as u64
}

#[inline(always)]
fn build_value(pid: u64, uid: u64) -> [u8; VALUE_LEN] {
    let mut out = MaybeUninit::<[u8; VALUE_LEN]>::uninit();
    let out_ptr = out.as_mut_ptr().cast::<u8>();
    let pid_b = pid.to_ne_bytes();
    let uid_b = uid.to_ne_bytes();

    let mut i = 0;
    while i < 8 {
        unsafe {
            ptr::write(out_ptr.add(i), pid_b[i]);
            ptr::write(out_ptr.add(8 + i), uid_b[i]);
        }
        i += 1;
    }

    let _ = unsafe {
        aya_ebpf::helpers::r#gen::bpf_get_current_comm(
            out_ptr.wrapping_add(16).cast(),
            TASK_COMM_LEN as u32,
        )
    };
    unsafe { out.assume_init() }
}

#[inline(always)]
fn read_value_pid(v: &[u8; VALUE_LEN]) -> u64 {
    u64::from_ne_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]])
}

#[kprobe]
pub fn kprobe__tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let skp = sk as u64;
    let _ = tcpsock.insert(&pid_tgid, &skp, 0);
    0
}

#[kretprobe]
pub fn kretprobe__tcp_v4_connect(_ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(skp) = unsafe { tcpsock.get(&pid_tgid) }.copied() else {
        return 0;
    };
    let sk = skp as *const u8;

    let Some(dport) = read_kernel_u16(sk, SKC_DPORT_OFF) else {
        let _ = tcpsock.remove(&pid_tgid);
        return 0;
    };
    let Some(sport) = read_kernel_u16(sk, SKC_NUM_OFF) else {
        let _ = tcpsock.remove(&pid_tgid);
        return 0;
    };
    let Some(daddr) = read_kernel_u32(sk, SKC_DADDR_OFF) else {
        let _ = tcpsock.remove(&pid_tgid);
        return 0;
    };
    let Some(saddr) = read_kernel_u32(sk, SKC_RCV_SADDR_OFF) else {
        let _ = tcpsock.remove(&pid_tgid);
        return 0;
    };

    let mut key = MaybeUninit::<[u8; TCP_KEY_LEN]>::uninit();
    let kp = key.as_mut_ptr().cast::<u8>();
    write_u16_ne(kp, 0, sport);
    write_u32_ne(kp, 2, daddr);
    write_u16_ne(kp, 6, dport);
    write_u32_ne(kp, 8, saddr);
    let key = unsafe { key.assume_init() };

    let value = build_value(current_pid(), current_uid_u64());
    let _ = tcpMap.insert(&key, &value, 0);
    let _ = tcpsock.remove(&pid_tgid);
    0
}

#[kprobe]
pub fn kprobe__tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let skp = sk as u64;
    let _ = tcpv6sock.insert(&pid_tgid, &skp, 0);
    0
}

#[kretprobe]
pub fn kretprobe__tcp_v6_connect(_ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(skp) = unsafe { tcpv6sock.get(&pid_tgid) }.copied() else {
        return 0;
    };
    let sk = skp as *const u8;

    let Some(dport) = read_kernel_u16(sk, SKC_DPORT_OFF) else {
        let _ = tcpv6sock.remove(&pid_tgid);
        return 0;
    };
    let Some(sport) = read_kernel_u16(sk, SKC_NUM_OFF) else {
        let _ = tcpv6sock.remove(&pid_tgid);
        return 0;
    };
    let Some(daddr) = read_kernel_arr16(sk, SKC_V6_DADDR_OFF) else {
        let _ = tcpv6sock.remove(&pid_tgid);
        return 0;
    };
    let Some(saddr) = read_kernel_arr16(sk, SKC_V6_RCV_SADDR_OFF) else {
        let _ = tcpv6sock.remove(&pid_tgid);
        return 0;
    };

    let mut key = MaybeUninit::<[u8; TCPV6_KEY_LEN]>::uninit();
    let kp = key.as_mut_ptr().cast::<u8>();
    write_u16_ne(kp, 0, sport);
    write_arr16(kp, 2, &daddr);
    write_u16_ne(kp, 18, dport);
    write_arr16(kp, 20, &saddr);
    let key = unsafe { key.assume_init() };

    let value = build_value(current_pid(), current_uid_u64());
    let _ = tcpv6Map.insert(&key, &value, 0);
    let _ = tcpv6sock.remove(&pid_tgid);
    0
}

#[kprobe]
pub fn kprobe__udp_sendmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let Some(msg) = ctx.arg::<*const u8>(1) else {
        return 0;
    };

    let msg_name = read_kernel_u64(msg, MSG_NAME_OFF).unwrap_or(0) as *const u8;

    let mut key = MaybeUninit::<[u8; UDP_KEY_LEN]>::uninit();
    let kp = key.as_mut_ptr().cast::<u8>();

    let mut dport = read_kernel_u16(msg_name, SOCKADDR_IN_PORT_OFF).unwrap_or(0);
    let daddr = if dport != 0 {
        read_kernel_u32(msg_name, SOCKADDR_IN_ADDR_OFF).unwrap_or(0)
    } else {
        dport = read_kernel_u16(sk, SKC_DPORT_OFF).unwrap_or(0);
        read_kernel_u32(sk, SKC_DADDR_OFF).unwrap_or(0)
    };

    let sport = read_kernel_u16(sk, SKC_NUM_OFF).unwrap_or(0);
    let mut saddr = read_kernel_u32(sk, SKC_RCV_SADDR_OFF).unwrap_or(0);

    if saddr == 0 {
        let control = read_kernel_u64(msg, MSG_CONTROL_OFF).unwrap_or(0) as *const u8;
        saddr = read_kernel_u32(control, IN_PKTINFO_SPEC_DST_OFF).unwrap_or(0);
    }

    if dport == 0 {
        return 0;
    }

    write_u16_ne(kp, 0, sport);
    write_u32_ne(kp, 2, daddr);
    write_u16_ne(kp, 6, dport);
    write_u32_ne(kp, 8, saddr);
    let key = unsafe { key.assume_init() };

    let pid = current_pid();
    if let Some(v) = unsafe { udpMap.get(&key) }
        && read_value_pid(v) == pid
    {
        return 0;
    }

    let value = build_value(pid, current_uid_u64());
    let _ = udpMap.insert(&key, &value, 0);
    0
}

#[kprobe]
pub fn kprobe__udpv6_sendmsg(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let Some(msg) = ctx.arg::<*const u8>(1) else {
        return 0;
    };

    let msg_name = read_kernel_u64(msg, MSG_NAME_OFF).unwrap_or(0) as *const u8;

    let mut key = MaybeUninit::<[u8; UDPV6_KEY_LEN]>::uninit();
    let kp = key.as_mut_ptr().cast::<u8>();

    let mut dport = read_kernel_u16(sk, SKC_DPORT_OFF).unwrap_or(0);
    let (daddr_p1, daddr_p2) = if dport != 0 {
        let Some(p1) = read_kernel_u64(sk, SKC_V6_DADDR_OFF) else {
            return 0;
        };
        let Some(p2) = read_kernel_u64(sk, SKC_V6_DADDR_OFF + 8) else {
            return 0;
        };
        (p1, p2)
    } else {
        dport = read_kernel_u16(msg_name, SOCKADDR_IN6_PORT_OFF).unwrap_or(0);
        let Some(p1) = read_kernel_u64(msg_name, SOCKADDR_IN6_ADDR_OFF) else {
            return 0;
        };
        let Some(p2) = read_kernel_u64(msg_name, SOCKADDR_IN6_ADDR_OFF + 8) else {
            return 0;
        };
        (p1, p2)
    };

    let sport = read_kernel_u16(sk, SKC_NUM_OFF).unwrap_or(0);
    let Some(mut saddr_p1) = read_kernel_u64(sk, SKC_V6_RCV_SADDR_OFF) else {
        return 0;
    };
    let Some(mut saddr_p2) = read_kernel_u64(sk, SKC_V6_RCV_SADDR_OFF + 8) else {
        return 0;
    };

    if saddr_p1 == 0 {
        let control = read_kernel_u64(msg, MSG_CONTROL_OFF).unwrap_or(0) as *const u8;
        if let Some(p1) = read_kernel_u64(control, IN6_PKTINFO_ADDR_OFF) {
            saddr_p1 = p1;
        }
        if let Some(p2) = read_kernel_u64(control, IN6_PKTINFO_ADDR_OFF + 8) {
            saddr_p2 = p2;
        }
    }

    if dport == 0 {
        return 0;
    }

    write_u16_ne(kp, 0, sport);
    write_u64_ne(kp, 2, daddr_p1);
    write_u64_ne(kp, 10, daddr_p2);
    write_u16_ne(kp, 18, dport);
    write_u64_ne(kp, 20, saddr_p1);
    write_u64_ne(kp, 28, saddr_p2);
    let key = unsafe { key.assume_init() };

    let pid = current_pid();
    if let Some(v) = unsafe { udpv6Map.get(&key) }
        && read_value_pid(v) == pid
    {
        return 0;
    }

    let value = build_value(pid, current_uid_u64());
    let _ = udpv6Map.insert(&key, &value, 0);
    0
}

#[kprobe]
pub fn kprobe__inet_dgram_connect(ctx: ProbeContext) -> u32 {
    let Some(skt) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let Some(sa) = ctx.arg::<*const u8>(1) else {
        return 0;
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let skt_u64 = skt as u64;
    let sa_u64 = sa as u64;
    let _ = tcpsock.insert(&pid_tgid, &skt_u64, 0);
    let _ = icmpsock.insert(&pid_tgid, &sa_u64, 0);
    0
}

#[kretprobe]
pub fn kretprobe__inet_dgram_connect(_ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    let Some(sktp) = unsafe { tcpsock.get(&pid_tgid) }.copied() else {
        return 0;
    };
    let Some(sap) = unsafe { icmpsock.get(&pid_tgid) }.copied() else {
        let _ = tcpsock.remove(&pid_tgid);
        return 0;
    };

    let Some(sk_u64) = read_kernel_u64(sktp as *const u8, SOCKET_SK_OFF) else {
        let _ = tcpsock.remove(&pid_tgid);
        let _ = icmpsock.remove(&pid_tgid);
        return 0;
    };
    let sk = sk_u64 as *const u8;

    let proto = read_kernel::<u8>(sk.wrapping_add(SK_PROTOCOL_OFF).cast()).unwrap_or(0);
    let fam = read_kernel::<u8>(sk.wrapping_add(SK_FAMILY_OFF).cast()).unwrap_or(0);

    let pid = current_pid();
    let uid = current_uid_u64();
    let value = build_value(pid, uid);

    if fam == AF_INET {
        let mut key = MaybeUninit::<[u8; UDP_KEY_LEN]>::uninit();
        let kp = key.as_mut_ptr().cast::<u8>();

        let sa = sap as *const u8;
        let mut daddr = read_kernel_u32(sa, SOCKADDR_IN_ADDR_OFF).unwrap_or(0);
        let mut dport = read_kernel_u16(sa, SOCKADDR_IN_PORT_OFF).unwrap_or(0);
        if dport == 0 {
            dport = read_kernel_u16(sk, SKC_DPORT_OFF).unwrap_or(0);
            daddr = read_kernel_u32(sk, SKC_DADDR_OFF).unwrap_or(0);
        }
        let sport = read_kernel_u16(sk, SKC_NUM_OFF).unwrap_or(0).to_be();
        let saddr = read_kernel_u32(sk, SKC_RCV_SADDR_OFF).unwrap_or(0);

        write_u16_ne(kp, 0, sport);
        write_u32_ne(kp, 2, daddr);
        write_u16_ne(kp, 6, dport);
        write_u32_ne(kp, 8, saddr);
        let key = unsafe { key.assume_init() };

        if dport != 0 && daddr != 0 && proto == IPPROTO_UDP {
            let _ = udpMap.insert(&key, &value, 0);
        }
    } else if fam == AF_INET6 {
        let mut key = MaybeUninit::<[u8; UDPV6_KEY_LEN]>::uninit();
        let kp = key.as_mut_ptr().cast::<u8>();
        let sa = sap as *const u8;

        let mut dport = read_kernel_u16(sk, SKC_DPORT_OFF).unwrap_or(0);
        let (daddr_p1, daddr_p2) = if dport != 0 {
            let Some(p1) = read_kernel_u64(sk, SKC_V6_DADDR_OFF) else {
                let _ = tcpsock.remove(&pid_tgid);
                let _ = icmpsock.remove(&pid_tgid);
                return 0;
            };
            let Some(p2) = read_kernel_u64(sk, SKC_V6_DADDR_OFF + 8) else {
                let _ = tcpsock.remove(&pid_tgid);
                let _ = icmpsock.remove(&pid_tgid);
                return 0;
            };
            (p1, p2)
        } else {
            dport = read_kernel_u16(sa, SOCKADDR_IN6_PORT_OFF).unwrap_or(0);
            let Some(p1) = read_kernel_u64(sa, SOCKADDR_IN6_ADDR_OFF) else {
                let _ = tcpsock.remove(&pid_tgid);
                let _ = icmpsock.remove(&pid_tgid);
                return 0;
            };
            let Some(p2) = read_kernel_u64(sa, SOCKADDR_IN6_ADDR_OFF + 8) else {
                let _ = tcpsock.remove(&pid_tgid);
                let _ = icmpsock.remove(&pid_tgid);
                return 0;
            };
            (p1, p2)
        };

        let sport = read_kernel_u16(sk, SKC_NUM_OFF).unwrap_or(0);
        let Some(saddr_p1) = read_kernel_u64(sk, SKC_V6_RCV_SADDR_OFF) else {
            let _ = tcpsock.remove(&pid_tgid);
            let _ = icmpsock.remove(&pid_tgid);
            return 0;
        };
        let Some(saddr_p2) = read_kernel_u64(sk, SKC_V6_RCV_SADDR_OFF + 8) else {
            let _ = tcpsock.remove(&pid_tgid);
            let _ = icmpsock.remove(&pid_tgid);
            return 0;
        };

        write_u16_ne(kp, 0, sport);
        write_u64_ne(kp, 2, daddr_p1);
        write_u64_ne(kp, 10, daddr_p2);
        write_u16_ne(kp, 18, dport);
        write_u64_ne(kp, 20, saddr_p1);
        write_u64_ne(kp, 28, saddr_p2);
        let key = unsafe { key.assume_init() };

        if dport != 0 && proto == IPPROTO_UDP {
            let _ = udpv6Map.insert(&key, &value, 0);
        }
    }

    let _ = tcpsock.remove(&pid_tgid);
    let _ = icmpsock.remove(&pid_tgid);
    0
}

#[kprobe]
pub fn kprobe__udp_tunnel6_xmit_skb(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(1) else {
        return 0;
    };
    let Some(saddr_ptr) = ctx.arg::<*const u8>(4) else {
        return 0;
    };
    let Some(daddr_ptr) = ctx.arg::<*const u8>(5) else {
        return 0;
    };
    let Some(sport_ptr) = ctx.arg::<*const u8>(9) else {
        return 0;
    };
    let Some(dport_ptr) = ctx.arg::<*const u8>(10) else {
        return 0;
    };

    let Some(sport_net) = read_kernel::<u16>(sport_ptr.cast()) else {
        return 0;
    };
    let Some(dport) = read_kernel::<u16>(dport_ptr.cast()) else {
        return 0;
    };
    if dport == 0 || sport_net == 0 {
        return 0;
    }

    let sport = ntohs(sport_net);

    let Some(tun_saddr) = read_kernel_arr16(saddr_ptr, 0) else {
        return 0;
    };
    let Some(tun_daddr) = read_kernel_arr16(daddr_ptr, 0) else {
        return 0;
    };

    let Some(inet_daddr) = read_kernel_arr16(sk, SKC_V6_DADDR_OFF) else {
        return 0;
    };
    let Some(inet_saddr) = read_kernel_arr16(sk, SKC_V6_RCV_SADDR_OFF) else {
        return 0;
    };

    let pid = current_pid();
    let value = build_value(pid, current_uid_u64());

    let mut key_inet = MaybeUninit::<[u8; UDPV6_KEY_LEN]>::uninit();
    let kip = key_inet.as_mut_ptr().cast::<u8>();
    write_u16_ne(kip, 0, sport);
    write_arr16(kip, 2, &inet_daddr);
    write_u16_ne(kip, 18, dport);
    write_arr16(kip, 20, &inet_saddr);
    let key_inet = unsafe { key_inet.assume_init() };

    if let Some(v) = unsafe { udpv6Map.get(&key_inet) }
        && read_value_pid(v) != pid
    {
        let _ = udpv6Map.insert(&key_inet, &value, 0);
    } else if unsafe { udpv6Map.get(&key_inet) }.is_none() {
        let _ = udpv6Map.insert(&key_inet, &value, 0);
    }

    let mut key_tunnel = MaybeUninit::<[u8; UDPV6_KEY_LEN]>::uninit();
    let ktp = key_tunnel.as_mut_ptr().cast::<u8>();
    write_u16_ne(ktp, 0, sport);
    write_arr16(ktp, 2, &tun_daddr);
    write_u16_ne(ktp, 18, dport);
    write_arr16(ktp, 20, &tun_saddr);
    let key_tunnel = unsafe { key_tunnel.assume_init() };

    if let Some(v) = unsafe { udpv6Map.get(&key_tunnel) }
        && read_value_pid(v) != pid
    {
        let _ = udpv6Map.insert(&key_tunnel, &value, 0);
    } else if unsafe { udpv6Map.get(&key_tunnel) }.is_none() {
        let _ = udpv6Map.insert(&key_tunnel, &value, 0);
    }

    // Keep legacy localhost fallback semantics when tunnel addresses are empty.
    if tun_saddr == [0; 16] && tun_daddr == [0; 16] {
        let mut loopback = [0u8; 16];
        loopback[15] = 1;

        let mut key_loop = MaybeUninit::<[u8; UDPV6_KEY_LEN]>::uninit();
        let klp = key_loop.as_mut_ptr().cast::<u8>();
        write_u16_ne(klp, 0, sport);
        write_arr16(klp, 2, &loopback);
        write_u16_ne(klp, 18, dport);
        write_arr16(klp, 20, &loopback);
        let key_loop = unsafe { key_loop.assume_init() };
        let _ = udpv6Map.insert(&key_loop, &value, 0);
    }

    0
}

#[kprobe]
pub fn kprobe__iptunnel_xmit(ctx: ProbeContext) -> u32 {
    let Some(skb) = ctx.arg::<*const u8>(2) else {
        return 0;
    };

    let Some(src) = ctx.arg::<u32>(3) else {
        return 0;
    };
    let Some(dst) = ctx.arg::<u32>(4) else {
        return 0;
    };

    let Some(transport_header) = read_kernel_u16(skb, SKB_TRANSPORT_HEADER_OFF) else {
        return 0;
    };
    let Some(head_ptr) = read_kernel_u64(skb, SKB_HEAD_OFF) else {
        return 0;
    };

    let udp_hdr = (head_ptr as *const u8).wrapping_add(transport_header as usize);
    let Some(sport_net) = read_kernel::<u16>(udp_hdr.cast()) else {
        return 0;
    };
    let Some(dport) = read_kernel::<u16>(udp_hdr.wrapping_add(2).cast()) else {
        return 0;
    };
    if dport == 0 || sport_net == 0 {
        return 0;
    }
    let sport = ntohs(sport_net);

    let mut key = MaybeUninit::<[u8; UDP_KEY_LEN]>::uninit();
    let kp = key.as_mut_ptr().cast::<u8>();
    write_u16_ne(kp, 0, sport);
    write_u32_ne(kp, 2, dst);
    write_u16_ne(kp, 6, dport);
    write_u32_ne(kp, 8, src);
    let key = unsafe { key.assume_init() };

    let pid = current_pid();
    if let Some(v) = unsafe { udpMap.get(&key) }
        && read_value_pid(v) == pid
    {
        return 0;
    }

    let value = build_value(pid, current_uid_u64());
    let _ = udpMap.insert(&key, &value, 0);
    0
}

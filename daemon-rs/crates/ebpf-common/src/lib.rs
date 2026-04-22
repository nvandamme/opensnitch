#![no_std]

pub mod maps {
    pub const EVENTS_MAP_NAME: &str = "events";
    pub const EVENTS_MAP_MAX_ENTRIES: u32 = 1 << 24;
}

pub mod dns {
    pub const AF_INET: u32 = 2;
    pub const AF_INET6: u32 = 10;
    /// Sentinel `addr_type` emitted when a DNS lookup failed (EAI_* or h_errno).
    /// The first four bytes of `ip` carry the `i32` error code in native-endian order.
    pub const AF_UNRESOLVED: u32 = 0xFFFF_FFFE;
    pub const IP_LEN: usize = 16;
    pub const HOST_LEN: usize = 252;
    pub const NODE_LEN: usize = 256;
    pub const MAX_ALIASES: usize = 5;
    pub const MAX_IPS: usize = 30;
    pub const ADDRINFO_ARGS_MAX_ENTRIES: u32 = 256;
    pub const GETHOSTBYNAME_ARGS_MAX_ENTRIES: u32 = 256;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct DnsEvent {
        pub addr_type: u32,
        pub ip: [u8; IP_LEN],
        pub host: [u8; HOST_LEN],
    }

    impl DnsEvent {
        pub const LEN: usize = core::mem::size_of::<Self>();

        pub const fn zeroed() -> Self {
            Self {
                addr_type: 0,
                ip: [0; IP_LEN],
                host: [0; HOST_LEN],
            }
        }
    }
}

pub mod process {
    pub const EV_TYPE_EXEC: u64 = 1;
    pub const EV_TYPE_EXECVEAT: u64 = 2;
    pub const EV_TYPE_FORK: u64 = 3;
    pub const EV_TYPE_SCHED_EXIT: u64 = 4;

    pub const MAX_PATH_LEN: usize = 4096;
    pub const MAX_ARGS: usize = 20;
    pub const MAX_ARG_LEN: usize = 256;
    pub const TASK_COMM_LEN: usize = 16;

    pub const COMPLETE_ARGS: u8 = 0;
    pub const INCOMPLETE_ARGS: u8 = 1;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct ExecEvent {
        pub ev_type: u64,
        pub pid: u32,
        pub uid: u32,
        pub ppid: u32,
        pub ret_code: u32,
        pub args_count: u8,
        pub args_partial: u8,
        pub filename: [u8; MAX_PATH_LEN],
        pub args: [[u8; MAX_ARG_LEN]; MAX_ARGS],
        pub comm: [u8; TASK_COMM_LEN],
    }

    impl ExecEvent {
        pub const HDR_LEN: usize = 26;
        pub const LEN: usize = core::mem::size_of::<Self>();
    }
}

pub mod pinning {
    pub const LEGACY_CONN_ROOT: &str = "/sys/fs/bpf/opensnitch";
    pub const LEGACY_PROC_ROOT: &str = "/sys/fs/bpf/opensnitch_procs";
    pub const LEGACY_DNS_ROOT: &str = "/sys/fs/bpf/opensnitch_dns";

    pub const AYA_CONN_ROOT: &str = "/sys/fs/bpf/opensnitch-rs";
    pub const AYA_PROC_ROOT: &str = "/sys/fs/bpf/opensnitch-rs/procs";
    pub const AYA_DNS_ROOT: &str = "/sys/fs/bpf/opensnitch-rs/dns";

    pub const TCP_MAP_NAME: &str = "tcpMap";
    pub const LEGACY_CONN_TCP_MAP_PATH: &str = "/sys/fs/bpf/opensnitch/tcpMap";
    pub const AYA_CONN_TCP_MAP_PATH: &str = "/sys/fs/bpf/opensnitch-rs/tcpMap";
    pub const LEGACY_PROC_EVENTS_PATH: &str = "/sys/fs/bpf/opensnitch_procs/events";
    pub const AYA_PROC_EVENTS_PATH: &str = "/sys/fs/bpf/opensnitch-rs/procs/events";
    pub const LEGACY_DNS_EVENTS_PATH: &str = "/sys/fs/bpf/opensnitch_dns/events";
    pub const AYA_DNS_EVENTS_PATH: &str = "/sys/fs/bpf/opensnitch-rs/dns/events";
}

pub mod abi {
    pub const ABI_VERSION: u16 = 1;
}
// eBPF map metadata is consumed only when at least one eBPF backend path is enabled.
#[cfg(any(
    feature = "aya-ebpf",
    feature = "libbpf-ebpf",
    feature = "native-ebpf-ringbuf"
))]
#[derive(Debug, Clone)]
pub struct RawBpfMap {
    pub id: u32,
    pub name: String,
    pub max_entries: u32,
}

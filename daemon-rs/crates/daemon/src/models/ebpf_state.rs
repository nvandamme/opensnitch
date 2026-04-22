use serde::Deserialize;

// eBPF map metadata is consumed only when at least one eBPF backend path is enabled.
#[cfg(any(
    feature = "aya-ebpf",
    feature = "libbpf-ebpf",
    feature = "native-ebpf-ringbuf"
))]
#[derive(Debug, Clone, Deserialize)]
pub struct RawBpfMap {
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub max_entries: u32,
}

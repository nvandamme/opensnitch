use serde::Deserialize;

// eBPF map metadata is consumed only when at least one eBPF backend path is enabled.
#[cfg_attr(
    not(any(
        feature = "aya-ebpf",
        feature = "libbpf-ebpf",
        feature = "native-ebpf-ringbuf"
    )),
    allow(dead_code)
)]
#[derive(Debug, Clone, Deserialize)]
pub struct RawBpfMap {
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub max_entries: u32,
}

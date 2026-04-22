#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FirewallBackend {
    #[default]
    Nftables,
    Iptables,
    // OpenWrt backend remains an optional target-specific runtime backend.
    #[allow(dead_code)]
    OpenWrtUci,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallState {
    pub enabled: bool,
    pub backend: FirewallBackend,
}

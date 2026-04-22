#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FirewallBackend {
    #[default]
    Nftables,
    Iptables,
    #[cfg_attr(not(feature = "openwrt"), allow(dead_code))]
    OpenWrtUci,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallState {
    pub enabled: bool,
    pub backend: FirewallBackend,
}

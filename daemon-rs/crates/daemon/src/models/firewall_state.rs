#[derive(Debug, Clone, Copy, Default)]
pub enum FirewallBackend {
    #[default]
    Nftables,
    Iptables,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallState {
    pub enabled: bool,
    pub backend: FirewallBackend,
}

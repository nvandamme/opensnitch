#[derive(Debug, Clone, Copy, Default)]
pub enum FirewallBackend {
    #[default]
    Nftables,
    Iptables,
}

impl FirewallBackend {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "iptables" => Self::Iptables,
            _ => Self::Nftables,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallState {
    pub enabled: bool,
    pub backend: FirewallBackend,
}

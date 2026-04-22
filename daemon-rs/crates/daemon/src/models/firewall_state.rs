use crate::utils::name_parsing::normalized_name;

#[derive(Debug, Clone, Copy, Default)]
pub enum FirewallBackend {
    #[default]
    Nftables,
    Iptables,
}

impl FirewallBackend {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "iptables" => Self::Iptables,
            _ => Self::Nftables,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
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

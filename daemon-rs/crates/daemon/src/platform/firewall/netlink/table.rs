#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct NftTable {
    family: String,
    name: String,
}

impl NftTable {
    pub(crate) fn new(family: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            name: name.into(),
        }
    }

    pub(crate) fn opensnitch() -> Self {
        Self::new("inet", "opensnitch")
    }

    pub(crate) fn family(&self) -> &str {
        &self.family
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) const SYSFW_TAG_PREFIX: &[u8] = b"opensnitch-sysfw:";
pub(super) const INTERCEPTION_DNS_TAG: &str = "opensnitch-queue-dns";
pub(super) const INTERCEPTION_NON_TCP_TAG: &str = "opensnitch-queue-connections-non-tcp";
pub(super) const INTERCEPTION_TCP_SYN_TAG: &str = "opensnitch-queue-connections-tcp-syn";

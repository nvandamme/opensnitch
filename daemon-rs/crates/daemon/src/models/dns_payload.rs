use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswerRecord {
    pub host: Arc<str>,
    pub addresses: Arc<[IpAddr]>,
}

impl DnsAnswerRecord {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(host: impl Into<Arc<str>>, addresses: Arc<[IpAddr]>) -> Option<Self> {
        if addresses.is_empty() {
            return None;
        }

        Some(Self {
            host: host.into(),
            addresses,
        })
    }

    pub fn from_ip(host: impl Into<Arc<str>>, address: IpAddr) -> Self {
        Self {
            host: host.into(),
            addresses: Arc::<[IpAddr]>::from(vec![address]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPayload {
    Answers(DnsAnswerRecord),
    Alias { alias: Arc<str>, host: Arc<str> },
}

impl DnsPayload {
    pub fn answer(host: impl Into<Arc<str>>, address: IpAddr) -> Self {
        Self::Answers(DnsAnswerRecord::from_ip(host, address))
    }

    #[allow(dead_code)]
    pub fn answers(host: impl Into<Arc<str>>, addresses: Arc<[IpAddr]>) -> Option<Self> {
        DnsAnswerRecord::new(host, addresses).map(Self::Answers)
    }

    pub fn alias(alias: impl Into<Arc<str>>, host: impl Into<Arc<str>>) -> Self {
        Self::Alias {
            alias: alias.into(),
            host: host.into(),
        }
    }
}

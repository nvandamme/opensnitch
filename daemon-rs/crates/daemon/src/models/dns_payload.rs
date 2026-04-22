use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswerRecord {
    pub host: Arc<str>,
    pub addresses: Arc<[IpAddr]>,
}

impl DnsAnswerRecord {
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
    Alias {
        alias: Arc<str>,
        host: Arc<str>,
    },
    /// A DNS lookup was attempted but the resolver returned an error.
    /// `error_code` carries the EAI_* value for `getaddrinfo` failures, or
    /// `0` for `gethostbyname` failures (h_errno is not accessible from a
    /// uretprobe without an additional probe hook).
    // Produced only by specific DNS monitor backends; may be idle in minimal profiles.
    #[cfg_attr(not(feature = "native-ebpf-ringbuf"), allow(dead_code))]
    NxDomain {
        host: Arc<str>,
        error_code: i32,
    },
}

impl DnsPayload {
    pub fn answer(host: impl Into<Arc<str>>, address: IpAddr) -> Self {
        Self::Answers(DnsAnswerRecord::from_ip(host, address))
    }

    pub fn answers(host: impl Into<Arc<str>>, addresses: Arc<[IpAddr]>) -> Option<Self> {
        DnsAnswerRecord::new(host, addresses).map(Self::Answers)
    }

    pub fn alias(alias: impl Into<Arc<str>>, host: impl Into<Arc<str>>) -> Self {
        Self::Alias {
            alias: alias.into(),
            host: host.into(),
        }
    }

    // Constructor used by DNS backends that surface resolver error events.
    #[cfg_attr(not(feature = "native-ebpf-ringbuf"), allow(dead_code))]
    pub fn nxdomain(host: impl Into<Arc<str>>, error_code: i32) -> Self {
        Self::NxDomain {
            host: host.into(),
            error_code,
        }
    }
}

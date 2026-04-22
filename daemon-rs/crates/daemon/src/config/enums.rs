use crate::{
    models::{
        config_runtime::{
            AskFallbackPolicy, AuthMode, ClientAuthType, DefaultAction, DefaultDuration,
            FirewallPersistenceMode, LoggerSinkConfig, ProcMonitorMethod, StatsConfig,
        },
        config_storage::{RawConfig, RawLoggerConfig},
    },
    utils::name_parsing::normalized_name,
};

impl Default for ClientAuthType {
    fn default() -> Self {
        Self::Simple
    }
}

impl ClientAuthType {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "tls-simple" => Self::TlsSimple,
            "tls-mutual" => Self::TlsMutual,
            _ => Self::Simple,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::TlsSimple => "tls-simple",
            Self::TlsMutual => "tls-mutual",
        }
    }
}

impl Default for AuthMode {
    fn default() -> Self {
        Self::Legacy
    }
}

impl AuthMode {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "local-only" | "local_only" | "localonly" => Self::LocalOnly,
            "local+remote" | "local-remote" | "local_remote" | "localremote" => {
                Self::LocalRemoteCapabilities
            }
            _ => Self::Legacy,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::LocalOnly => "local-only",
            Self::LocalRemoteCapabilities => "local+remote",
        }
    }
}

impl From<RawLoggerConfig> for LoggerSinkConfig {
    fn from(raw: RawLoggerConfig) -> Self {
        Self {
            name: raw.name,
            format: raw.format,
            protocol: raw.protocol,
            server: raw.server,
            write_timeout: raw.write_timeout,
            connect_timeout: raw.connect_timeout,
            tag: raw.tag,
            workers: raw.workers.unwrap_or(0),
            max_connect_attempts: raw.max_connect_attempts.unwrap_or(0),
        }
    }
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            max_events: 250,
            max_stats: 25,
            workers: 6,
        }
    }
}

impl DefaultAction {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "reject" => Self::Reject,
            "drop" | "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn from_raw_config_json(raw_config_json: &str) -> Option<Self> {
        // wire notification payloads are always JSON; use a canonical .json path for format detection
        let raw = RawConfig::parse_normalized_for_path(
            std::path::Path::new("notification-payload.json"),
            raw_config_json,
        )
        .ok()?;
        Some(Self::from_name(&raw.default_action))
    }

    pub fn allows(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn rejects(self) -> bool {
        matches!(self, Self::Reject)
    }
}

impl AskFallbackPolicy {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "allow" => Self::Allow,
            "deny" | "drop" => Self::Drop,
            "default" => Self::DefaultAction,
            _ => Self::DefaultAction,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::DefaultAction => "default",
            Self::Allow => "allow",
            Self::Drop => "drop",
        }
    }
}

impl DefaultDuration {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "always" => Self::Always,
            "untilrestart" => Self::Restart,
            _ => Self::Once,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }
}

impl ProcMonitorMethod {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "audit" => Self::Audit,
            "ebpf" => Self::Ebpf,
            _ => Self::Proc,
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }
}

impl Default for FirewallPersistenceMode {
    fn default() -> Self {
        Self::Durable
    }
}

impl FirewallPersistenceMode {
    fn parse_from_name(name: &str) -> Self {
        match normalized_name(name).as_str() {
            "live" | "liveonly" | "live-only" | "runtime-only" | "runtime" => Self::LiveOnly,
            "durable" | "persistent" | "persist" | "system" | "system-wide" => Self::Durable,
            _ => Self::default(),
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::parse_from_name(name)
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::LiveOnly => "live-only",
            Self::Durable => "durable",
        }
    }
}

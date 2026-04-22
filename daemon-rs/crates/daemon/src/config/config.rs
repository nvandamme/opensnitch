use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use super::{
    AskFallbackPolicy, AuditSinkConfig, AuthMode, ClientAuthConfig, ClientAuthType,
    ClientTlsOptions, Config, DefaultAction, DefaultDuration, LoggerSinkConfig, ProcMonitorMethod,
    StatsConfig,
};
use crate::{
    models::{audit::AuditSeverity, config_storage::RawConfig, firewall_state::FirewallBackend},
    services::firewall::parse_firewall_backend,
    services::storage::{StorageFormat, StorageService},
    utils::name_parsing::{case_folded, normalized_name},
};

impl Default for Config {
    fn default() -> Self {
        let config_path = Self::dev_default_path("daemon/data/default-config.json");
        let rules_path = Self::dev_default_path("daemon/data/rules");
        let firewall_config_path = Self::dev_default_path("daemon/data/system-fw.json");
        let tasks_config_path = Self::dev_default_path("daemon/data/tasks/tasks.json");
        let network_aliases_path = Self::dev_default_path("daemon/data/network_aliases.json");

        Self {
            client_addr: "http://127.0.0.1:50051".to_string(),
            log_level: 0,
            log_utc: true,
            log_micro: false,
            log_file: None,
            loggers: Vec::new(),
            auth_mode: AuthMode::Legacy,
            client_auth: ClientAuthConfig::default(),
            local_control_allowed_principals: None,
            local_control_allowed_group_gids: None,
            remote_principal_bindings: None,
            rules_enable_checksums: false,
            default_action: DefaultAction::Allow,
            ask_timeout_policy: AskFallbackPolicy::DefaultAction,
            default_duration: DefaultDuration::Once,
            intercept_unknown: false,
            proc_monitor_method: ProcMonitorMethod::Ebpf,
            ebpf_modules_path: PathBuf::from("/usr/lib/opensnitchd/ebpf"),
            firewall_backend: FirewallBackend::default(),
            firewall_monitor_interval: "10s".to_string(),
            firewall_queue_num: 0,
            firewall_queue_bypass: true,
            firewall_config_path,
            rules_path,
            network_aliases_path,
            tasks_config_path,
            stats: StatsConfig::default(),
            raw_json: "{}".to_string(),
            config_path,
            audit_socket_path: PathBuf::from("/var/run/audispd_events"),
            audit_sinks: AuditSinkConfig::default(),
            flush_conns_on_start: true,
            gc_percent: None,
        }
    }
}

impl Config {
    fn canonical_config_json_key(key: &str) -> Option<&'static str> {
        let lowered = case_folded(key);
        match lowered.as_str() {
            "server" => Some("Server"),
            "loglevel" => Some("LogLevel"),
            "logutc" => Some("LogUTC"),
            "logmicro" => Some("LogMicro"),
            "defaultaction" => Some("DefaultAction"),
            "asktimeoutpolicy" => Some("AskTimeoutPolicy"),
            "defaultduration" => Some("DefaultDuration"),
            "interceptunknown" => Some("InterceptUnknown"),
            "procmonitormethod" => Some("ProcMonitorMethod"),
            "firewall" => Some("Firewall"),
            "fwoptions" => Some("FwOptions"),
            "rules" => Some("Rules"),
            "tasksoptions" => Some("TasksOptions"),
            "tasks" => Some("Tasks"),
            "audit" => Some("Audit"),
            "ebpf" => Some("Ebpf"),
            "stats" => Some("Stats"),
            "internal" => Some("Internal"),
            "address" => Some("Address"),
            "authentication" => Some("Authentication"),
            "logfile" => Some("LogFile"),
            "loggers" => Some("Loggers"),
            "mode" => Some("Mode"),
            "type" => Some("Type"),
            "tlsoptions" => Some("TLSOptions"),
            "cacert" => Some("CACert"),
            "servercert" => Some("ServerCert"),
            "serverkey" => Some("ServerKey"),
            "clientcert" => Some("ClientCert"),
            "clientkey" => Some("ClientKey"),
            "clientauthtype" => Some("ClientAuthType"),
            "skipverify" => Some("SkipVerify"),
            "allowedprincipals" => Some("AllowedPrincipals"),
            "allowedusers" => Some("AllowedUsers"),
            "remoteprincipalbindings" => Some("RemotePrincipalBindings"),
            "certfingerprint" => Some("CertFingerprint"),
            "certsubject" => Some("CertSubject"),
            "certsan" => Some("CertSAN"),
            "localprincipal" => Some("LocalPrincipal"),
            "localuser" => Some("LocalUser"),
            "capabilities" => Some("Capabilities"),
            "allowedgroups" => Some("AllowedGroups"),
            "uid" => Some("UID"),
            "gid" => Some("GID"),
            "name" => Some("Name"),
            "format" => Some("Format"),
            "protocol" => Some("Protocol"),
            "writetimeout" => Some("WriteTimeout"),
            "connecttimeout" => Some("ConnectTimeout"),
            "tag" => Some("Tag"),
            "workers" => Some("Workers"),
            "maxconnectattempts" => Some("MaxConnectAttempts"),
            "monitorinterval" => Some("MonitorInterval"),
            "configpath" => Some("ConfigPath"),
            "queuenum" => Some("QueueNum"),
            "queuebypass" => Some("QueueBypass"),
            "path" => Some("Path"),
            "enablechecksums" => Some("EnableChecksums"),
            "networkaliasesfile" => Some("NetworkAliasesFile"),
            "audispsocketpath" => Some("AudispSocketPath"),
            "sinkfile" => Some("SinkFile"),
            "sinksyslog" => Some("SinkSyslog"),
            "sinkloglines" => Some("SinkLogLines"),
            "verbosehotpath" => Some("VerboseHotPath"),
            "minseverity" => Some("MinSeverity"),
            "modulespath" => Some("ModulesPath"),
            "maxevents" => Some("MaxEvents"),
            "maxstats" => Some("MaxStats"),
            "gcpercent" => Some("GCPercent"),
            "flushconnsonstart" => Some("FlushConnsOnStart"),
            _ => None,
        }
    }

    fn normalize_config_json_keys(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(obj) => {
                let mut normalized = serde_json::Map::with_capacity(obj.len());
                for (key, value) in obj {
                    let normalized_key =
                        Self::canonical_config_json_key(&key).unwrap_or(key.as_str());
                    normalized.insert(
                        normalized_key.to_string(),
                        Self::normalize_config_json_keys(value),
                    );
                }
                serde_json::Value::Object(normalized)
            }
            serde_json::Value::Array(values) => serde_json::Value::Array(
                values
                    .into_iter()
                    .map(Self::normalize_config_json_keys)
                    .collect::<Vec<_>>(),
            ),
            _ => value,
        }
    }

    fn resolve_runtime_path(configured: &str, dev_fallback_rel: &str) -> PathBuf {
        let configured = configured.trim();
        if !configured.is_empty() {
            let configured_path = PathBuf::from(configured);
            if configured_path.exists() {
                return configured_path;
            }
        }

        Self::dev_default_path(dev_fallback_rel)
    }

    fn dev_default_path(rel_path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(rel_path)
    }

    /// Load config from the standard search order, with an optional CLI override.
    ///
    /// Resolution priority (highest first, DESIGN_RULES §7):
    ///   1. `cli_path` — explicit `--config-file` flag
    ///   2. `OPENSNITCH_CONFIG_FILE` env var
    ///   3. `/etc/opensnitchd/default-config.json` if it exists
    ///   4. Dev-tree fallback `daemon/data/default-config.json`
    pub fn load_from_default_locations_with_override(
        cli_path: Option<&std::path::Path>,
        main_storage_format: Option<StorageFormat>,
    ) -> Result<Self> {
        let env_path = std::env::var_os("OPENSNITCH_CONFIG_FILE").map(PathBuf::from);
        let cli_path = cli_path.and_then(|p| p.exists().then(|| p.to_path_buf()));
        let effective_main_storage_format =
            main_storage_format.unwrap_or(StorageFormat::compiled_default());
        let preferred_default_path = Some(effective_main_storage_format)
            .map(|format| {
                PathBuf::from(format!(
                    "/etc/opensnitchd/default-config.{}",
                    format.canonical_extension()
                ))
            })
            .filter(|path| path.exists());
        let preferred_dev_path = Some(effective_main_storage_format)
            .map(|format| {
                Self::dev_default_path(&format!(
                    "daemon/data/default-config.{}",
                    format.canonical_extension()
                ))
            })
            .filter(|path| path.exists());

        #[cfg(feature = "storage-format-json")]
        let default_path = PathBuf::from("/etc/opensnitchd/default-config.json");

        #[cfg(feature = "storage-format-json")]
        let default_path = default_path.exists().then_some(default_path);

        #[cfg(not(feature = "storage-format-json"))]
        let default_path: Option<PathBuf> = None;

        let config_path = cli_path
            .or_else(|| env_path.filter(|path| path.exists()))
            .or(preferred_default_path)
            .or(default_path)
            .or(preferred_dev_path)
            .unwrap_or_else(|| {
                Self::dev_default_path(&format!(
                    "daemon/data/default-config.{}",
                    effective_main_storage_format.canonical_extension()
                ))
            });

        Self::load_from_path(&config_path)
    }

    /// Load config from canonical default locations with no CLI override.
    pub fn load_from_default_locations() -> Result<Self> {
        Self::load_from_default_locations_with_override(None, None)
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw_json = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        Self::from_raw_json(path, raw_json)
    }

    pub fn from_raw_json(path: &Path, raw_json: String) -> Result<Self> {
        let parsed_value: serde_json::Value =
            StorageService::parse_with_storage_format_for_path(path, &raw_json)
                .with_context(|| format!("failed to parse config file {}", path.display()))?;
        let normalized_value = Self::normalize_config_json_keys(parsed_value);
        let raw: RawConfig = serde_json::from_value(normalized_value)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        let local_control_allowed_principals =
            Self::parse_local_control_allowed_principals(&raw.server.authentication);
        let local_control_allowed_group_gids =
            Self::parse_local_control_allowed_group_gids(&raw.server.authentication);
        let remote_principal_bindings =
            Self::parse_remote_principal_bindings(&raw.server.authentication);

        Ok(Self {
            stats: StatsConfig {
                max_events: raw
                    .stats
                    .max_events
                    .unwrap_or(StatsConfig::default().max_events),
                max_stats: raw
                    .stats
                    .max_stats
                    .unwrap_or(StatsConfig::default().max_stats),
                workers: raw.stats.workers.unwrap_or(StatsConfig::default().workers),
            },
            client_addr: raw.server.address,
            log_level: raw.log_level.unwrap_or(0),
            log_utc: raw.log_utc.unwrap_or(true),
            log_micro: raw.log_micro.unwrap_or(false),
            log_file: {
                let value = raw.server.log_file.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(value))
                }
            },
            loggers: raw
                .server
                .loggers
                .into_iter()
                .map(LoggerSinkConfig::from)
                .collect(),
            auth_mode: AuthMode::from_name(&raw.server.authentication.mode),
            client_auth: ClientAuthConfig {
                auth_type: ClientAuthType::from_name(&raw.server.authentication.r#type),
                tls_options: ClientTlsOptions {
                    ca_cert: raw.server.authentication.tls_options.ca_cert,
                    server_cert: raw.server.authentication.tls_options.server_cert,
                    server_key: raw.server.authentication.tls_options.server_key,
                    client_cert: raw.server.authentication.tls_options.client_cert,
                    client_key: raw.server.authentication.tls_options.client_key,
                    client_auth_type: raw.server.authentication.tls_options.client_auth_type,
                    skip_verify: raw
                        .server
                        .authentication
                        .tls_options
                        .skip_verify
                        .unwrap_or(false),
                },
            },
            local_control_allowed_principals,
            local_control_allowed_group_gids,
            remote_principal_bindings,
            rules_enable_checksums: raw.rules.enable_checksums.unwrap_or(false),
            default_action: DefaultAction::from_name(&raw.default_action),
            ask_timeout_policy: AskFallbackPolicy::from_name(
                raw.ask_timeout_policy.as_deref().unwrap_or_default(),
            ),
            default_duration: DefaultDuration::from_name(&raw.default_duration),
            intercept_unknown: raw.intercept_unknown.unwrap_or(false),
            proc_monitor_method: ProcMonitorMethod::from_name(&raw.proc_monitor_method),
            ebpf_modules_path: if raw.ebpf.modules_path.trim().is_empty() {
                PathBuf::from("/usr/lib/opensnitchd/ebpf")
            } else {
                PathBuf::from(raw.ebpf.modules_path.trim())
            },
            firewall_backend: parse_firewall_backend(&raw.firewall),
            firewall_monitor_interval: {
                let value = raw.fw_options.monitor_interval.trim();
                if value.is_empty() {
                    "10s".to_string()
                } else {
                    value.to_string()
                }
            },
            firewall_queue_num: raw.fw_options.queue_num.unwrap_or(0),
            firewall_queue_bypass: raw.fw_options.queue_bypass.unwrap_or(true),
            firewall_config_path: Self::resolve_runtime_path(
                &raw.fw_options.config_path,
                "daemon/data/system-fw.json",
            ),
            flush_conns_on_start: raw.internal.flush_conns_on_start.unwrap_or(true),
            gc_percent: raw.internal.gc_percent,
            rules_path: Self::resolve_runtime_path(&raw.rules.path, "daemon/data/rules"),
            network_aliases_path: Self::resolve_runtime_path(
                &raw.rules.network_aliases_file,
                "daemon/data/network_aliases.json",
            ),
            tasks_config_path: Self::resolve_runtime_path(
                &raw.tasks_options.config_path,
                "daemon/data/tasks/tasks.json",
            ),
            raw_json,
            config_path: path.to_path_buf(),
            audit_socket_path: if raw.audit.audisp_socket_path.trim().is_empty() {
                PathBuf::from("/var/run/audispd_events")
            } else {
                PathBuf::from(raw.audit.audisp_socket_path.trim())
            },
            audit_sinks: AuditSinkConfig {
                sink_file: {
                    let v = raw.audit.sink_file.trim();
                    if v.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(v))
                    }
                },
                sink_syslog: raw.audit.sink_syslog.unwrap_or(false),
                sink_log_lines: raw.audit.sink_log_lines.unwrap_or(true),
                verbose_hot_path: raw.audit.verbose_hot_path.unwrap_or(false),
                min_severity: Self::parse_audit_min_severity(raw.audit.min_severity.as_str()),
            },
        })
    }

    fn parse_audit_min_severity(raw: &str) -> AuditSeverity {
        match normalized_name(raw) {
            name if name == "error" => AuditSeverity::Error,
            name if name == "warn" || name == "warning" => AuditSeverity::Warning,
            name if name == "info" => AuditSeverity::Info,
            name if name == "debug" => AuditSeverity::Debug,
            _ => AuditSeverity::Debug,
        }
    }

    pub fn with_client_addr_override(mut self, client_addr: Option<&str>) -> Self {
        if let Some(client_addr) = client_addr.filter(|value| !value.is_empty()) {
            self.client_addr = client_addr.to_string();
        }
        self
    }

    /// Override `auth_mode` with the value of `--auth-mode` from the CLI.
    ///
    /// Accepted values (case-insensitive):
    /// - `legacy`
    /// - `local-only` (`local_only`, `localonly`)
    /// - `local+remote` (`local-remote`, `local_remote`, `localremote`)
    pub fn with_auth_mode_override(mut self, auth_mode: Option<&str>) -> Self {
        let Some(auth_mode) = auth_mode.filter(|value| !value.trim().is_empty()) else {
            return self;
        };

        match normalized_name(auth_mode).as_str() {
            "legacy" => self.auth_mode = AuthMode::Legacy,
            "local-only" | "local_only" | "localonly" => self.auth_mode = AuthMode::LocalOnly,
            "local+remote" | "local-remote" | "local_remote" | "localremote" => {
                self.auth_mode = AuthMode::LocalRemoteCapabilities
            }
            _ => {
                tracing::warn!(
                    auth_mode,
                    "ignoring unsupported --auth-mode value; keeping config-defined mode"
                );
            }
        }

        self
    }

    /// Override `rules_path` with the value of `--rules-path` from the CLI.
    /// Mirrors the Go daemon's post-load `rules.Reload(rulesPath)` behaviour.
    pub fn with_rules_path_override(mut self, rules_path: Option<&std::path::Path>) -> Self {
        if let Some(path) = rules_path {
            self.rules_path = path.to_path_buf();
        }
        self
    }
}

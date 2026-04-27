use serde::Deserialize;
use serde_json::Value;

use crate::models::rule::record::RuleRecord;

#[derive(Debug, Deserialize)]
pub struct IncomingTaskNotification {
    #[serde(alias = "Name", alias = "NAME")]
    pub name: String,
    #[serde(default, alias = "Data", alias = "DATA")]
    pub data: Value,
}

#[derive(Debug, Clone)]
pub struct TaskNotification {
    pub notification_id: u64,
    pub name: String,
    /// Raw JSON string decoded from the wire notification payload.
    /// Opaque bag-of-bytes: do not parse inside this struct or the channel layer.
    pub data: String,
}

/// Serde input type for subscription notification `data` JSON payloads.
///
/// Used by `SUBSCRIPTION_APPLY`, `SUBSCRIPTION_DELETE`, `SUBSCRIPTION_REFRESH`,
/// and `SUBSCRIPTION_DEPLOY` notification actions arriving on the daemon's
/// Notifications gRPC stream.
#[cfg(feature = "subscriptions")]
#[derive(Deserialize, Default)]
pub struct IncomingSubscriptionNotification {
    #[serde(default)]
    pub subscriptions: Vec<IncomingSubscription>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub force: bool,
}

#[cfg(feature = "subscriptions")]
#[derive(Deserialize, Default)]
pub struct IncomingSubscription {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum ClientCommand {
    SetInterception {
        notification_id: u64,
        enabled: bool,
    },
    SetFirewall {
        notification_id: u64,
        enabled: bool,
    },
    ReloadFirewall {
        notification_id: u64,
        firewall: Option<crate::platform::firewall::config::FirewallConfig>,
    },
    ApplyConfig {
        notification_id: u64,
        raw_json: String,
    },
    EnableRules {
        notification_id: u64,
        rules: Vec<RuleRecord>,
    },
    DisableRules {
        notification_id: u64,
        rules: Vec<RuleRecord>,
    },
    StartTask(TaskNotification),
    StopTask(TaskNotification),
    UpsertRules {
        notification_id: u64,
        rules: Vec<RuleRecord>,
    },
    DeleteRules {
        notification_id: u64,
        rule_names: Vec<String>,
    },
    // Reserved command variant for runtime task pausing parity and future UI control hooks.
    #[allow(dead_code)]
    PauseRuntimeTasks,
    ResumeRuntimeTasks,
    StopRuntimeTasks,
    SetLogLevel {
        notification_id: u64,
        level: i32,
    },
    Shutdown {
        notification_id: u64,
    },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WireStatistics {
    pub daemon_version: String,
    pub rules: u64,
    pub uptime: u64,
    pub dns_responses: u64,
    pub connections: u64,
    pub ignored: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub rule_hits: u64,
    pub rule_misses: u64,
    pub by_proto: std::collections::HashMap<String, u64>,
    pub by_address: std::collections::HashMap<String, u64>,
    pub by_host: std::collections::HashMap<String, u64>,
    pub by_port: std::collections::HashMap<String, u64>,
    pub by_uid: std::collections::HashMap<String, u64>,
    pub by_executable: std::collections::HashMap<String, u64>,
    pub events: Vec<WireEvent>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WireEvent {
    pub time: String,
    pub connection: Option<WireConnection>,
    pub rule: Option<WireRule>,
    pub unixnano: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionStatistics {
    pub total: u64,
    pub ready: u64,
    pub error: u64,
    pub refresh_count: u64,
    pub refresh_errors: u64,
    pub by_status: std::collections::HashMap<String, u64>,
    pub by_group: std::collections::HashMap<String, u64>,
    pub by_node: std::collections::HashMap<String, u64>,
    pub events: Vec<WireSubscriptionEvent>,
    pub rule_subscriptions: Vec<WireRuleSubscriptionEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionEvent {
    pub time: String,
    pub subscription: Option<WireSubscription>,
    pub action: i32,
    pub unixnano: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireRuleSubscriptionEntry {
    pub rule: String,
    pub subscriptions: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireStringInt {
    pub key: String,
    pub value: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireConnection {
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u32,
    pub dst_ip: String,
    pub dst_host: String,
    pub dst_port: u32,
    pub user_id: u32,
    pub process_id: u32,
    pub process_path: String,
    pub process_cwd: String,
    pub process_args: Vec<String>,
    pub process_env: std::collections::HashMap<String, String>,
    pub process_checksums: std::collections::HashMap<String, String>,
    pub process_tree: Vec<WireStringInt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireProcess {
    pub pid: u64,
    pub ppid: u64,
    pub uid: u64,
    pub comm: String,
    pub path: String,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
    pub cwd: String,
    pub checksums: std::collections::HashMap<String, String>,
    pub io_reads: u64,
    pub io_writes: u64,
    pub net_reads: u64,
    pub net_writes: u64,
    pub process_tree: Vec<WireStringInt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireAlertData {
    Text(String),
    Connection(WireConnection),
    Process(WireProcess),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireAlert {
    pub id: u64,
    pub alert_type: i32,
    pub action: i32,
    pub priority: i32,
    pub what: i32,
    pub data: Option<WireAlertData>,
}

impl Default for WireAlert {
    fn default() -> Self {
        Self {
            id: 0,
            alert_type: 0,
            action: 0,
            priority: 0,
            what: 0,
            data: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WireSubscribeConfig {
    pub id: u64,
    pub name: String,
    pub version: String,
    pub is_firewall_running: bool,
    pub config: String,
    pub log_level: u32,
    pub rules: Vec<WireRule>,
    pub system_firewall: Option<WireSysFirewall>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WirePingRequest {
    pub id: u64,
    pub stats: Option<WireStatistics>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WirePingReply {
    pub id: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireAlertReply {
    pub id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireAlertType {
    Info = 0,
    Warning = 1,
    Error = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireAlertWhat {
    Generic = 0,
    Connection = 1,
    KernelEvent = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireAlertAction {
    ShowAlert = 0,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireAlertPriority {
    Low = 0,
    Medium = 1,
    High = 2,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WireNotification {
    pub id: u64,
    pub action: i32,
    pub data: String,
    pub rules: Vec<WireRule>,
    pub sys_firewall: Option<WireSysFirewall>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireRule {
    pub created: i64,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub precedence: bool,
    pub nolog: bool,
    pub action: String,
    pub duration: String,
    pub operator: Option<WireRuleOperator>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireRuleOperator {
    pub type_name: String,
    pub operand: String,
    pub data: String,
    pub sensitive: bool,
    pub list: Vec<WireRuleOperator>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSysFirewall {
    pub enabled: bool,
    pub version: u32,
    pub rules: Vec<WireFwRule>,
    pub chains: Vec<WireFwChain>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireFwChain {
    pub name: String,
    pub table: String,
    pub family: String,
    pub priority: String,
    pub type_name: String,
    pub hook: String,
    pub policy: String,
    pub rules: Vec<WireFwRule>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireFwRule {
    pub table: String,
    pub chain: String,
    pub uuid: String,
    pub enabled: bool,
    pub position: u64,
    pub description: String,
    pub parameters: String,
    pub expressions: Vec<WireFwExpression>,
    pub target: String,
    pub target_parameters: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireFwExpression {
    pub statement: Option<WireFwStatement>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireFwStatement {
    pub op: String,
    pub name: String,
    pub values: Vec<WireFwStatementValue>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireFwStatementValue {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireNotificationReply {
    pub id: u64,
    pub code: i32,
    pub data: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireNotificationReplyCode {
    Ok = 0,
    Error = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireCommandAction {
    None = 0,
    EnableInterception = 1,
    DisableInterception = 2,
    EnableFirewall = 3,
    DisableFirewall = 4,
    ReloadFwRules = 5,
    ChangeConfig = 6,
    EnableRule = 7,
    DisableRule = 8,
    DeleteRule = 9,
    ChangeRule = 10,
    LogLevel = 11,
    Stop = 12,
    TaskStart = 13,
    TaskStop = 14,
}

impl WireCommandAction {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::EnableInterception,
            2 => Self::DisableInterception,
            3 => Self::EnableFirewall,
            4 => Self::DisableFirewall,
            5 => Self::ReloadFwRules,
            6 => Self::ChangeConfig,
            7 => Self::EnableRule,
            8 => Self::DisableRule,
            9 => Self::DeleteRule,
            10 => Self::ChangeRule,
            11 => Self::LogLevel,
            12 => Self::Stop,
            13 => Self::TaskStart,
            14 => Self::TaskStop,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub filename: String,
    pub groups: Vec<String>,
    pub enabled: bool,
    pub format: String,
    pub interval_seconds: u32,
    pub timeout_seconds: u32,
    pub max_bytes: u64,
    pub node: String,
    pub status: i32,
    pub last_updated: String,
    pub last_error: String,
    pub refresh_meta: Option<WireSubscriptionRefreshMetadata>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionRefreshMetadata {
    pub next_refresh_after: i64,
    pub consecutive_failures: u32,
    pub etag: String,
    pub last_modified: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionRequest {
    pub operation: i32,
    pub subscriptions: Vec<WireSubscription>,
    pub targets: Vec<String>,
    pub force: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionReply {
    pub operation: i32,
    pub errors: Vec<String>,
    pub accepted: bool,
    pub message: String,
    pub subscriptions: Vec<WireSubscription>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionCommand {
    pub id: u64,
    pub action: i32,
    pub data: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WireSubscriptionCommandAck {
    pub id: u64,
    pub action: i32,
    pub accepted: bool,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WireSubscriptionAction {
    Unspecified = 0,
    List = 1,
    Apply = 2,
    Delete = 3,
    Refresh = 4,
    Deploy = 5,
}

pub fn status_payload(status: &str) -> String {
    serde_json::json!({"status": status}).to_string()
}

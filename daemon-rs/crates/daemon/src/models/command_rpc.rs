use opensnitch_proto::pb;
use serde::Deserialize;
use serde_json::Value;

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
    pub data: Value,
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
        sys_firewall: Option<pb::SysFirewall>,
    },
    ApplyConfig {
        notification_id: u64,
        raw_json: String,
    },
    EnableRules {
        notification_id: u64,
        rules: Vec<pb::Rule>,
    },
    DisableRules {
        notification_id: u64,
        rules: Vec<pb::Rule>,
    },
    StartTask(TaskNotification),
    StopTask(TaskNotification),
    UpsertRules {
        notification_id: u64,
        rules: Vec<pb::Rule>,
    },
    DeleteRules {
        notification_id: u64,
        rule_names: Vec<String>,
    },
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

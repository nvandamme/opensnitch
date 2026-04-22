use std::sync::Arc;

use serde_json::Value;
use transport_wire_core::{decode_json_notification_payload, decode_json_value_payload};

use crate::models::task_config::{DownloaderTaskConfig, IocScannerTaskConfig};
use crate::utils::json_value;

use super::naming as task_runtime_naming;

#[derive(Clone)]
pub(crate) enum TaskRuntimePayload {
    PidMonitor {
        pid_raw: Option<String>,
        interval_raw: Option<String>,
    },
    NodeMonitor {
        node: Option<String>,
        interval_raw: Option<String>,
    },
    SocketsMonitor {
        interval_raw: Option<String>,
        family: Option<u8>,
        proto: Option<u8>,
        state: Option<u8>,
    },
    Looper {
        interval_raw: Option<String>,
    },
    Downloader {
        interval_raw: Option<String>,
        config: Option<Arc<DownloaderTaskConfig>>,
    },
    IocScanner {
        interval_raw: Option<String>,
        config: Option<Arc<IocScannerTaskConfig>>,
    },
}

impl TaskRuntimePayload {
    /// Construct from a raw JSON string arriving on the wire (gRPC task notification).
    /// This is the only place where raw JSON strings from task notification payloads
    /// are decoded; all downstream task code receives a typed `TaskRuntimePayload`.
    pub(crate) fn from_task_data_raw(task_name: &str, raw_json: &str) -> Self {
        let data: Value = decode_json_notification_payload(raw_json).unwrap_or_default();
        Self::from_task_data(task_name, data)
    }

    pub(crate) fn from_task_data(task_name: &str, data: Value) -> Self {
        let normalized = task_runtime_naming::normalized_task_name(task_name);
        let interval_raw = json_value::field_string_or_u64(&data, "interval");
        match normalized.as_str() {
            task_runtime_naming::TASK_PID_MONITOR => Self::PidMonitor {
                pid_raw: json_value::field_string_or_u64(&data, "pid").or_else(|| {
                    task_runtime_naming::task_instance_suffix(
                        task_name,
                        task_runtime_naming::TASK_PID_MONITOR,
                    )
                }),
                interval_raw,
            },
            task_runtime_naming::TASK_NODE_MONITOR => Self::NodeMonitor {
                node: json_value::field_string_or_u64(&data, "node").or_else(|| {
                    task_runtime_naming::task_instance_suffix(
                        task_name,
                        task_runtime_naming::TASK_NODE_MONITOR,
                    )
                }),
                interval_raw,
            },
            task_runtime_naming::TASK_SOCKETS_MONITOR => Self::SocketsMonitor {
                interval_raw,
                family: json_value::field_u8(&data, "family"),
                proto: json_value::field_u8(&data, "proto"),
                state: json_value::field_u8(&data, "state"),
            },
            task_runtime_naming::TASK_LOOPER => Self::Looper { interval_raw },
            task_runtime_naming::TASK_DOWNLOADER => {
                let config = decode_json_value_payload::<DownloaderTaskConfig>(data.clone())
                    .ok()
                    .map(Arc::new);
                Self::Downloader {
                    interval_raw,
                    config,
                }
            }
            task_runtime_naming::TASK_IOC_SCANNER => {
                let config = decode_json_value_payload::<IocScannerTaskConfig>(data.clone())
                    .ok()
                    .map(Arc::new);
                Self::IocScanner {
                    interval_raw,
                    config,
                }
            }
            _ => Self::Looper { interval_raw },
        }
    }

    pub(crate) fn interval_raw(&self) -> Option<&str> {
        match self {
            Self::PidMonitor { interval_raw, .. }
            | Self::NodeMonitor { interval_raw, .. }
            | Self::SocketsMonitor { interval_raw, .. }
            | Self::Looper { interval_raw }
            | Self::Downloader { interval_raw, .. }
            | Self::IocScanner { interval_raw, .. } => interval_raw.as_deref(),
        }
    }

    pub(crate) fn pid_raw(&self) -> Option<&str> {
        match self {
            Self::PidMonitor { pid_raw, .. } => pid_raw.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn node_name(&self) -> Option<&str> {
        match self {
            Self::NodeMonitor { node, .. } => node.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn sockets_family(&self) -> Option<u8> {
        match self {
            Self::SocketsMonitor { family, .. } => *family,
            _ => None,
        }
    }

    pub(crate) fn sockets_proto(&self) -> Option<u8> {
        match self {
            Self::SocketsMonitor { proto, .. } => *proto,
            _ => None,
        }
    }

    pub(crate) fn sockets_state(&self) -> Option<u8> {
        match self {
            Self::SocketsMonitor { state, .. } => *state,
            _ => None,
        }
    }

    pub(crate) fn downloader_config(&self) -> Option<Arc<DownloaderTaskConfig>> {
        match self {
            Self::Downloader { config, .. } => config.clone(),
            _ => None,
        }
    }

    pub(crate) fn ioc_scanner_config(&self) -> Option<Arc<IocScannerTaskConfig>> {
        match self {
            Self::IocScanner { config, .. } => config.clone(),
            _ => None,
        }
    }
}

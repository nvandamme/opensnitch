use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LegacyTaskResultPayload {
    #[serde(rename = "Type")]
    pub(crate) type_id: i32,
    #[serde(rename = "Data")]
    pub(crate) data: String,
}

impl LegacyTaskResultPayload {
    pub(crate) const TYPE_ID: i32 = 9999;

    pub(crate) fn new(data: impl Into<String>) -> Self {
        Self {
            type_id: Self::TYPE_ID,
            data: data.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TaskErrorPayload {
    #[serde(rename = "Task")]
    pub(crate) task: String,
    #[serde(rename = "Error")]
    pub(crate) error: String,
}

impl TaskErrorPayload {
    pub(crate) fn new(task: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            task: task.into(),
            error: error.into(),
        }
    }
}
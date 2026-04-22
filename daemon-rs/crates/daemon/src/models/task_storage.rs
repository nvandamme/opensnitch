use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TasksListFile {
    #[serde(default, rename = "tasks")]
    pub(crate) tasks: Vec<TasksListEntry>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TasksListEntry {
    #[serde(default, rename = "name")]
    pub(crate) name: String,
    #[serde(default, rename = "configfile")]
    pub(crate) config_file: String,
    #[serde(default, rename = "enabled")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct TaskDataFile {
    #[serde(default, rename = "parent")]
    pub(crate) parent: String,
    #[serde(default, rename = "name")]
    pub(crate) name: String,
    #[serde(default, rename = "data")]
    pub(crate) data: Value,
}

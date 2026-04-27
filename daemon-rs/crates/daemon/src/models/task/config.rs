use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct DownloaderTaskConfig {
    #[cfg(feature = "task-http")]
    #[serde(default)]
    pub(crate) timeout: String,
    #[cfg(feature = "task-http")]
    #[serde(default)]
    pub(crate) urls: Vec<DownloaderUrl>,
    #[serde(default)]
    pub(crate) notify: DownloaderNotify,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DownloaderNotify {
    #[serde(default)]
    pub(crate) enabled: bool,
}

#[cfg(feature = "task-http")]
#[derive(Debug, Deserialize)]
pub(crate) struct DownloaderUrl {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) remote: String,
    #[serde(default, rename = "localfile")]
    pub(crate) local_file: String,
    #[serde(default)]
    pub(crate) enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IocScannerTaskConfig {
    #[serde(default)]
    pub(crate) timeout: String,
    #[serde(default)]
    pub(crate) schedule: Vec<IocScheduleConfig>,
    #[serde(default)]
    pub(crate) tools: Vec<IocToolConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct IocScheduleConfig {
    #[serde(default)]
    pub(crate) time: Vec<String>,
    #[serde(default)]
    pub(crate) weekday: Vec<u8>,
    #[serde(default)]
    pub(crate) hour: Vec<u8>,
    #[serde(default)]
    pub(crate) minute: Vec<u8>,
    #[serde(default)]
    pub(crate) second: Vec<u8>,
    #[serde(default, rename = "repeat")]
    pub(crate) _repeat: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IocToolConfig {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) cmd: Vec<String>,
    #[serde(default)]
    pub(crate) options: IocToolOptions,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct IocToolOptions {
    #[serde(default, rename = "maxRunningTime")]
    pub(crate) max_running_time: String,
    #[serde(default)]
    pub(crate) reports: Vec<IocReportConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct IocReportConfig {
    #[serde(default)]
    pub(crate) r#type: String,
    #[serde(default)]
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) format: String,
    #[serde(default, rename = "sync")]
    pub(crate) _sync: bool,
}

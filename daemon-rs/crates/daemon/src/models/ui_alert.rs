#[derive(Debug, Clone)]
pub enum UiAlertData {
    Text(String),
    Connection(UiAlertConnection),
    Process(UiAlertProcess),
}

#[derive(Debug, Clone, Default)]
pub struct UiAlertStringInt {
    pub key: String,
    pub value: u32,
}

#[derive(Debug, Clone, Default)]
pub struct UiAlertProcess {
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
    pub process_tree: Vec<UiAlertStringInt>,
}

#[derive(Debug, Clone, Default)]
pub struct UiAlertConnection {
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
    pub process_tree: Vec<UiAlertStringInt>,
}

#[derive(Debug, Clone)]
pub struct UiAlert {
    pub alert_type: i32,
    pub what: i32,
    pub action: i32,
    pub priority: i32,
    pub data: UiAlertData,
}

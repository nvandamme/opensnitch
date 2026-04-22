#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub path: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env_preview: Vec<String>,
    pub process_hash: Option<String>,
    pub parent_chain: Vec<ProcessNode>,
}

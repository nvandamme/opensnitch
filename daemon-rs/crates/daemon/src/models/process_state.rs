use std::collections::HashMap;

use opensnitch_proto::pb;

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
    pub env_map: HashMap<String, String>,
    pub process_hash: Option<String>,
    pub process_hash_md5: Option<String>,
    pub process_hash_sha1: Option<String>,
    pub parent_chain: Vec<ProcessNode>,
}

impl ProcessInfo {
    pub(crate) fn to_proto_process(&self) -> pb::Process {
        pb::Process {
            pid: self.pid as u64,
            ppid: 0,
            uid: 0,
            comm: String::new(),
            path: self.path.clone(),
            args: self.args.clone(),
            env: if !self.env_map.is_empty() {
                self.env_map.clone()
            } else {
                self.env_preview
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect()
            },
            cwd: self.cwd.clone().unwrap_or_default(),
            checksums: {
                let mut checksums = std::collections::HashMap::new();
                if let Some(md5) = &self.process_hash_md5 {
                    checksums.insert("md5".to_string(), md5.clone());
                }
                if let Some(sha1) = &self.process_hash_sha1 {
                    checksums.insert("sha1".to_string(), sha1.clone());
                }
                if let Some(sha256) = &self.process_hash {
                    checksums.insert("sha256".to_string(), sha256.clone());
                }
                checksums
            },
            io_reads: 0,
            io_writes: 0,
            net_reads: 0,
            net_writes: 0,
            process_tree: self
                .parent_chain
                .iter()
                .map(|node| pb::StringInt {
                    key: node.path.clone(),
                    value: node.pid,
                })
                .collect(),
        }
    }
}

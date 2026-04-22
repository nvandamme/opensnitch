use std::collections::HashMap;

use crate::models::{
    connection_state::{ConnectionAttempt, TransportProtocol},
    process_state::ProcessInfo,
};

pub struct ProtoMapperAdapter;

impl ProtoMapperAdapter {
    pub fn to_proto_process(proc_info: &ProcessInfo) -> opensnitch_proto::pb::Process {
        opensnitch_proto::pb::Process {
            pid: proc_info.pid as u64,
            ppid: 0,
            uid: 0,
            comm: String::new(),
            path: proc_info.path.clone(),
            args: proc_info.args.clone(),
            env: Self::build_env_map(proc_info),
            cwd: proc_info.cwd.clone().unwrap_or_default(),
            checksums: Self::build_checksums(proc_info),
            io_reads: 0,
            io_writes: 0,
            net_reads: 0,
            net_writes: 0,
            process_tree: proc_info
                .parent_chain
                .iter()
                .map(|node| opensnitch_proto::pb::StringInt {
                    key: node.path.clone(),
                    value: node.pid,
                })
                .collect(),
        }
    }

    pub fn to_proto_connection(
        attempt: &ConnectionAttempt,
        proc_info: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> opensnitch_proto::pb::Connection {
        opensnitch_proto::pb::Connection {
            protocol: match attempt.protocol {
                TransportProtocol::Tcp => "tcp".into(),
                TransportProtocol::Udp => "udp".into(),
                TransportProtocol::UdpLite => "udplite".into(),
                TransportProtocol::Sctp => "sctp".into(),
                TransportProtocol::Icmp => "icmp".into(),
            },
            src_ip: attempt.src_addr.to_string(),
            src_port: attempt.src_port as u32,
            dst_ip: attempt.dst_addr.to_string(),
            dst_host: dst_host.unwrap_or_default().to_string(),
            dst_port: attempt.dst_port as u32,

            process_id: attempt.pid as u32,
            user_id: attempt.uid as u32,

            process_path: proc_info.path.clone(),
            process_args: proc_info.args.clone(),
            process_cwd: proc_info.cwd.clone().unwrap_or_default(),
            process_env: Self::build_env_map(proc_info),
            process_checksums: Self::build_checksums(proc_info),
            process_tree: proc_info
                .parent_chain
                .iter()
                .map(|node| opensnitch_proto::pb::StringInt {
                    key: node.path.clone(),
                    value: node.pid,
                })
                .collect(),
        }
    }

    fn build_checksums(proc_info: &ProcessInfo) -> HashMap<String, String> {
        let count = proc_info.process_hash_md5.is_some() as usize
            + proc_info.process_hash_sha1.is_some() as usize
            + proc_info.process_hash.is_some() as usize;
        let mut checksums = HashMap::with_capacity(count);
        if let Some(hash) = proc_info
            .process_hash_md5
            .as_ref()
            .filter(|v| !v.is_empty())
        {
            checksums.insert("md5".into(), hash.clone());
        }
        if let Some(hash) = proc_info
            .process_hash_sha1
            .as_ref()
            .filter(|v| !v.is_empty())
        {
            checksums.insert("sha1".into(), hash.clone());
        }
        if let Some(hash) = proc_info.process_hash.as_ref().filter(|v| !v.is_empty()) {
            checksums.insert("sha256".into(), hash.clone());
        }
        checksums
    }

    fn build_env_map(proc_info: &ProcessInfo) -> HashMap<String, String> {
        if !proc_info.env_map.is_empty() {
            return proc_info.env_map.clone();
        }
        if proc_info.env_preview.is_empty() {
            return HashMap::new();
        }
        let mut env = HashMap::with_capacity(proc_info.env_preview.len());
        for entry in &proc_info.env_preview {
            if let Some((key, value)) = entry.split_once('=') {
                env.insert(key.to_string(), value.to_string());
            }
        }
        env
    }
}

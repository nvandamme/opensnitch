use std::collections::HashMap;

use crate::models::{
    connection_state::{ConnectionAttempt, TransportProtocol},
    process_state::ProcessInfo,
};

pub struct ProtoMapperAdapter;

impl ProtoMapperAdapter {
    pub fn to_proto_connection(
        attempt: &ConnectionAttempt,
        proc_info: &ProcessInfo,
        dst_host: Option<&str>,
    ) -> opensnitch_proto::pb::Connection {
        let process_env = if !proc_info.env_map.is_empty() {
            proc_info.env_map.clone()
        } else if proc_info.env_preview.is_empty() {
            HashMap::new()
        } else {
            let mut env = HashMap::new();
            env.reserve(proc_info.env_preview.len());
            for entry in &proc_info.env_preview {
                let Some((key, value)) = entry.split_once('=') else {
                    continue;
                };
                env.insert(key.to_string(), value.to_string());
            }
            env
        };

        let mut process_checksums = HashMap::new();
        if let Some(hash) = proc_info
            .process_hash_md5
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            process_checksums.insert("md5".to_string(), hash.clone());
        }
        if let Some(hash) = proc_info
            .process_hash_sha1
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            process_checksums.insert("sha1".to_string(), hash.clone());
        }
        if let Some(hash) = proc_info
            .process_hash
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            process_checksums.insert("sha256".to_string(), hash.clone());
        }

        let process_tree = if proc_info.parent_chain.is_empty() {
            Vec::new()
        } else {
            let mut out = Vec::with_capacity(proc_info.parent_chain.len());
            for node in &proc_info.parent_chain {
                out.push(opensnitch_proto::pb::StringInt {
                    key: node.path.clone(),
                    value: node.pid,
                });
            }
            out
        };

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
            process_env,
            process_checksums,
            process_tree,
        }
    }
}
